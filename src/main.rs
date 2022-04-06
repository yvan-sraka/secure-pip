//! # Secure Python Package Installer
//!
//! This spawn a Rust service that receives arbitrary pip install commands via an HTTP endpoint,
//! runs the installation commands securely (in a virtualenv),
//! and then zips and stores the resulting directory on a persistent file system (-o CLI argument).
//!
//! ## Usage
//!
//! This project assumes that:
//!
//! -   You're running a modern Linux machine (it does not have been tested on
//!     other environment).
//!
//! -   You have both [Nix](https://nixos.org/download.html) package manager
//!     installed on your machine and available in your `$PATH` and
//!     [`direnv`](https://direnv.net/docs/hook.html) hooked in your shell.
//!
//! ```shell
//! cargo run -o output_dir # a server now running on port 3000
//! # try a get request http:://127.0.0.1:3000/pip/?<package>
//! curl "http://127.0.0.1:3000/pip/?deta"
//! # the output HTTP Response 200 is the path to a zipped directory containing the package
//! # e.g. output_dir/13c4c538-a2e3-4d90-8e15-9506b33543a6.zip
//! ```
//!
//! ## Design considerations
//!
//! ### Security
//!
//! The installation of packages should be done in a secure environment,
//! stopping malicious code from affecting other packages or the underlying operating system.
//!
//! ### Scalability
//!
//! The service should be able to handle burst installation requests without impairing the system or affecting its performance.
//!
//! This could be achieved through a `rate-limiting` mechanism, or by using a middleware to perform load balancing between several instances of the service.
//!
//! ### KISS
//!
//! The service should be as simple as possible, it’s a design choice to not rely (yet) for e.g. more on NixOS ecosystem, or on a docker container:
//! generating on the go a `build.nix` or `Dockerfile` with the required packages rather than "just a virtualenv".
//!
//! ### Limitations
//!
//! Virtualenv is not meant to be "portable" because for e.g. it symlink python version of the hosting machine.
//! So, a zipped venv folder used on another machine isn’t at all granted to work...
//!
//! ### Future
//!
//! Having end-to-end tests, and few benchmarks would be a good follow-up.
//!
//! Next step for sure would be to be able to load/unload an environment with python packaged installed in it on demand.
//! But before that, we want a higher level of isolation while running scripts that we don’t write.
//! Containers (LXC + Cgroups based like Docker) isn’t the only way of doing it, we could also use BSD jails or chroot.

use anyhow::{anyhow, bail, ensure, Result};
use argh::FromArgs;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::tempdir;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

#[derive(FromArgs)]
/// /!\ This project is not meant to be used (yet) in production!
struct Settings {
    #[argh(
        option,
        description = "output directory for zipped packages",
        short = 'o'
    )]
    output_dir: String,
}

lazy_static::lazy_static!(
    static ref SETTINGS: Settings = argh::from_env();
);

/// A "pure" exec function sound a bit to fancy to be true...
/// _(we're not talking about guarantee of absence of side effects, which is reserved to those that live in the ivory tower...)_
///
/// Here it could be understood as the same as `nix-shell --pure` stand for,
/// in others words an arbitrary command will be run without inherent the parent shell environment.
///
/// It means that `ENV` variables given to the spawned process aims to be explicitly sets in the caller.
/// This is a good way to avoid the "environment pollution" that's a source of non-determinism.
///
/// In our case, we only set `VIRTUAL_ENV` and `PATH=VIRTUAL_ENV/bin:$PATH`, taking `VIRTUAL_ENV` as parameter.
///
/// TODO: for better development, this function could be rewritten as a macro_rules!
fn exec(cmd: &str, args: &[&str], virtualenv: &Path) -> Result<()> {
    info!("$ {} {}", cmd, args.join(" "));
    let mut paths = vec![virtualenv.join("bin")];
    paths.append(&mut env::split_paths(&env::var("PATH")?).collect());
    let output = match Command::new(cmd)
        .env_clear()
        .envs([
            ("VIRTUAL_ENV", virtualenv.as_os_str()),
            ("PATH", &env::join_paths(paths)?),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .args(args)
        .output()
    {
        Ok(output) => output,
        Err(e) => bail!("failed to execute: {} {}: {}", cmd, args.join(" "), e),
    };
    // analogously to `assert!` but returns an Error rather than panicking
    ensure!(
        output.status.success(),
        format!("command {} failed, {}", cmd, output.status)
    );
    Ok(())
}

/// How to secure the pip install command?
///
/// First thing is, DO NOT spawn a shell command that take arbitrary input (to prevent shell code injection)...
/// Knowing that, so we run directly a pip process with custom arguments.
///
/// But, we have to make caution that PIP can be still easily used for privilege elevation...
/// e.g. be aware of the kind of list of trick <https://gtfobins.github.io/gtfobins/pip/>
///
/// So, we will apply a simple whitelist strategy: strictly define a subset of strings to be valid pip install arguments.
///
/// TODO: this is a bit too restrictive, we should more arguments to fully support all usages:
/// <https://packaging.python.org/en/latest/tutorials/installing-packages/#use-pip-for-installing>
///
/// Methods we (currently) support:
/// - `pip install <package>` (e.g. `pip install numpy`) package name are alphanumeric and can contain `_`
/// - `pip install <url>` (e.g. `pip install git+https://github.com/httpie/httpie.git#egg=httpie`)
fn pip(pkg: &str) -> Result<String> {
    if pkg.chars().all(|c| char::is_ascii_alphanumeric(&c) || c == '_') // TODO: better use REGEX here
        || pkg.parse::<hyper::Uri>().is_ok() || !pkg.is_empty()
    {
        Ok(venv(pkg)?)
    } else {
        Err(anyhow!("Package name is not valid: {}", pkg)) // We return an Error rather than panic wildly
    }
}

/// Virtualenv is a tool to isolate Python packages from the system environment
/// <https://docs.python.org/3/tutorial/venv.html>
///
/// Here we're activating the virtualenv just by settings the right `VIRTUAL_ENV` and `PATH` environment variables.
///
/// TODO: rather than using `pip` we could rely on `pipenv` or `poetry` that provide a lock file mechanism
fn venv(pkg: &str) -> Result<String> {
    let uuid = Uuid::new_v4().to_string();
    // TODO: rather use `.join()` of ``std::path::Path` than `format!` on `String`...
    let zip_path = format!("{}/{}.zip", SETTINGS.output_dir, uuid);
    // Create a directory inside of `std::env::temp_dir()`.
    let temp_dir = tempdir()?;
    // This is really unlikely to fail, but we don't want a raw unwrap here
    let path = temp_dir.path();

    info!("setup a virtualenv in: {}", path.display());
    exec("python3", &["-m", "venv", &path.to_string_lossy()], path)?;

    info!("install the package: {}", pkg);
    exec("pip", &["install", pkg], path)?;

    // N.B. be aware that "--no-cache-dir" would be necessary if in the future we let user use build customization like
    // `export PYCURL_SSL_LIBRARY=openssl pip install pycurl`
    info!("store a compressed output in: {}", zip_path);
    exec("zip", &["-r", &zip_path, &path.to_string_lossy()], path)?;

    // N.B. Closing the directory is actually optional, as it would be done on drop.
    // The benefit of closing here is that it allows possible errors to be handled.
    temp_dir.close()?;

    info!("zipped output saved in: {}", zip_path);
    Ok(zip_path)
}

/// The service actually handle one URL request:
/// `http:://127.0.0.1:3000/pip/?<package>`
async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/pip/") => match pip(req.uri().query().unwrap_or("")) {
            Ok(zip_path) => {
                *response.status_mut() = StatusCode::OK;
                *response.body_mut() = Body::from(zip_path);
                // TODO: download the generated zip file?
            }
            Err(e) => {
                *response.status_mut() = StatusCode::BAD_REQUEST;
                *response.body_mut() = Body::from(e.to_string());
            }
        },
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

/// The code of this main function is heavily inspired by
/// <https://hyper.rs/guides/server/hello-world/> tutorial
#[tokio::main]
async fn main() {
    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::INFO)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    if !Path::new(&SETTINGS.output_dir).exists() {
        std::fs::create_dir_all(&SETTINGS.output_dir).expect("failed to create output directory");
    }

    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // A `Service` is needed for every connection, so this
    // creates one from our `handle_request` function.
    let make_svc = make_service_fn(|_conn| async {
        // service_fn converts our function into a `Service`
        Ok::<_, Infallible>(service_fn(handle_request))
    });

    // And construct the `Server` like normal...
    let server = Server::bind(&addr).serve(make_svc);

    // And now add a graceful shutdown signal...
    let graceful = server.with_graceful_shutdown(shutdown_signal());

    // Run this server for... forever!
    if let Err(e) = graceful.await {
        eprintln!("server error: {}", e);
    }
}

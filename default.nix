let
  # Pinned nixpkgs, deterministic (hermetic) build. Last updated: 4/4/22.
  pkgs = import (fetchTarball ("https://github.com/NixOS/nixpkgs/archive/eeeac2fbf89a3b1b0f088d5a94030b505fce4f4e.tar.gz")) { };
in
{ pythonPackageName ? "python3"
, python ? pkgs.${pythonPackageName}
}:

rec {
  pythonDependencies = (python.withPackages
    (ps: [
      ps.pip
    ]));

  shell = pkgs.mkShell {
    nativeBuildInputs = with pkgs; [
      pythonDependencies
      zip
      # Rust tooling
      cargo
      rustc
    ];
  };
}

{
  description = "embassy flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix/monthly";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, fenix, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let 
        probe-rs-overlay = (final: prev: {
          probe-rs-tools = prev.probe-rs-tools.overrideAttrs {
            cargoBuildFeatures = [ "remote" ];
          };
        }); 
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            fenix.overlays.default 
            probe-rs-overlay 
          ];
        };
      in
      {
        devShells.default =
        let
          profile = pkgs.fenix.complete;
          std-lib = pkgs.fenix.targets.thumbv7em-none-eabihf.latest;
          rust-toolchain = pkgs.fenix.combine [
            profile.rustc-unwrapped
            profile.rust-src
            profile.cargo
            profile.rustfmt
            profile.clippy
            std-lib.rust-std
          ];
        in
        pkgs.mkShell {
          buildInputs = with pkgs; [
            rust-toolchain
            rust-analyzer-nightly

            # extra cargo tools
            cargo-edit
            cargo-expand

            # for flashing
            probe-rs-tools
          ];

          # set the rust src for rust_analyzer
          RUST_SRC_PATH = "${rust-toolchain}/lib/rustlib/src/rust/library";
					# set default defmt log level
					DEFMT_LOG = "debug";
        };
      }
    );
}

{
  description = "rust-sandbox (rsb) — rootless Linux process isolation engine in pure Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "rust-sandbox";
            version = "0.2.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            doCheck = false;
            postInstall = ''
              install -Dm644 target/*/release/librsb_ffi.so "$out/lib/librsb_ffi.so" || true
              install -Dm644 bindings/c/rsb.h "$out/include/rsb.h"
            '';
            meta = with pkgs.lib; {
              description = "Rootless Linux process isolation engine, CLI, and C/Python FFI library in pure Rust";
              homepage = "https://github.com/Shura5860/rust-sandbox";
              license = with licenses; [ mit asl20 ];
              platforms = platforms.linux;
              mainProgram = "rsb";
            };
          };
        });
    };
}

{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    gcc
    pkg-config
    openssl
    rustc
  ];
}

#!/bin/zsh

set -e

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-Dwarnings"
export RUSTDOCFLAGS="-Dwarnings"

cargo fmt --all
cargo clippy --release --all-targets --fix --allow-dirty
act -W '.github/workflows/build_and_tests.yaml'

@echo off
set CARGO_TERM_COLOR=always
set RUSTFLAGS=-Dwarnings
set RUSTDOCFLAGS=-Dwarnings

cargo fmt --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --release --all-targets --fix --allow-dirty
if %errorlevel% neq 0 exit /b %errorlevel%

act -W '.github/workflows/build_and_tests.yaml'
if %errorlevel% neq 0 exit /b %errorlevel%

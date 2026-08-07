#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

/// Regression test: `get_cli_args` defines the subcommand as `passwd` and
/// `async_main` must dispatch on the same name. It used to match on
/// "change-password", so `rencfs passwd` died with "Invalid subcommand"
/// before ever reaching `run_change_password`.
#[test]
fn passwd_subcommand_is_dispatched() {
    let data_dir = tempfile::tempdir().unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rencfs"));
    cmd.args(["passwd", "--data-dir", data_dir.path().to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // rpassword reads from /dev/tty, not stdin; detach from the controlling
    // terminal so the password prompt fails fast instead of waiting for
    // keyboard input when tests are run from an interactive shell
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let output = cmd.output().expect("failed to run rencfs");

    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !all.contains("Invalid subcommand"),
        "passwd subcommand was not dispatched: {all}"
    );
    assert!(
        all.contains("Enter old password"),
        "run_change_password was not reached: {all}"
    );
}

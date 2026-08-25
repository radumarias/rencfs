use anyhow::Result;

mod keyring;

mod run;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        eprintln!("sorry but this platform is not supported!");
        eprintln!("Bye!");
        return Ok(());
    }

    run::run().await
}

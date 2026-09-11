use anyhow::Result;

mod keyring;

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod run;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        eprintln!("he he, not yet ready for this platform, but soon my friend, soon :)");
        eprintln!("Bye!");
        return Ok(());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    run::run().await
}
//! Windows-specific run module for rencfs

use anyhow::Result;
use std::path::PathBuf;
use tracing::info;

pub async fn run() -> Result<()> {
    info!("Starting rencfs for Windows...");
    
    let args: Vec<String> = std::env::args().collect();
    
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help();
        return Ok(());
    }
    
    let mountpoint = args
        .iter()
        .position(|a| a == "-m" || a == "--mount")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            eprintln!("Error: Mount point required on Windows (-m <path>)");
            std::process::exit(1);
        });
    
    let data_dir = args
        .iter()
        .position(|a| a == "-d" || a == "--data-dir")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".rencfs"));
    
    let read_only = args.contains(&"--read-only".to_string());
    
    info!("Mount point: {:?}", mountpoint);
    info!("Data directory: {:?}", data_dir);
    info!("Read only: {}", read_only);
    
    let password = rpassword::prompt_password("Password: ").unwrap();
    
    let cipher = args
        .iter()
        .position(|a| a == "--cipher")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.parse::<crate::crypto::Cipher>().unwrap_or(crate::crypto::Cipher::XChacha12Poly1305))
        .unwrap_or(crate::crypto::Cipher::XChacha12Poly1305);
    
    let fs = crate::encryptedfs::EncryptedFs::new(
        data_dir,
        &password,
        cipher,
        false,
        None,
    )?;
    
    let mp = crate::mount::create_mount_point(
        &mountpoint,
        &data_dir,
        Box::new(|| async { Ok(password.clone()) }),
        cipher,
        false,
        false,
        read_only,
    );
    
    let handle = mp.mount().await?;
    
    info!("Filesystem mounted at {:?}. Press Ctrl+C to unmount.", mountpoint);
    
    tokio::signal::ctrl_c().await?;
    
    info!("Unmounting...");
    handle.umount().await?;
    
    Ok(())
}

fn print_help() {
    println!(r#"
rencfs - Encrypted filesystem for Windows

Usage: rencfs [OPTIONS]

Options:
    -m, --mount <PATH>     Mount point (required on Windows)
    -d, --data-dir <PATH>  Data directory (default: .rencfs)
        --cipher <CIPHER>  Encryption cipher (default: XChacha12Poly1305)
        --read-only        Mount as read-only
    -h, --help            Show this help message

Example:
    rencfs -m X: -d C:\Users\You\.rencfs

Note: WinFSP must be installed for this to work.
"#);
}

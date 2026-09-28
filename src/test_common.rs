use std::future::Future;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::{env, fs};

use shush_rs::SecretString;
use tempfile::NamedTempFile;

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CopyFileRangeReq, CreateFileAttr, EncryptedFs, FileType, PasswordProvider,
};

#[allow(dead_code)]
pub static TESTS_DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let tmp = if env::var("RENCFS_RUN_ON_GH")
        .unwrap_or_else(|_| String::new())
        .eq("1")
    {
        NamedTempFile::new_in(".")
            .unwrap()
            .into_temp_path()
            .to_path_buf()
    } else {
        let tmp = NamedTempFile::new().unwrap().into_temp_path();
        fs::remove_file(tmp.to_str().unwrap()).expect("cannot remove tmp file");
        tmp.to_path_buf()
    };
    println!("tmp {}", tmp.clone().to_string_lossy());
    tmp.parent()
        .expect("oops, we don't have a parent")
        .join("rencfs-test-data")
});

tokio::task_local! {
    pub static CURRENT_FS: Arc<EncryptedFs>;
}

#[allow(dead_code)]
pub const fn create_attr(kind: FileType) -> CreateFileAttr {
    CreateFileAttr {
        kind,
        perm: 0,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

#[derive(Debug, Clone)]
pub struct TestSetup {
    #[allow(dead_code)]
    pub key: &'static str,
    pub read_only: bool,
}

#[allow(dead_code)]
pub struct PasswordProviderImpl {}
impl PasswordProvider for PasswordProviderImpl {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str("password").unwrap())
    }
}

#[allow(dead_code)]
#[allow(clippy::future_not_send)]
pub async fn run_test<T>(init: TestSetup, t: T)
where
    T: Future,
{
    let test_id = rand::random::<u64>();
    let path = TESTS_DATA_DIR.join(format!("{}_{test_id}", init.key));
    let read_only = init.read_only;
    let data_dir_str = path.to_str().unwrap();
    let _ = fs::create_dir_all(data_dir_str);

    let fs = EncryptedFs::new(
        Path::new(data_dir_str).to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        read_only,
    )
    .await
    .unwrap();

    CURRENT_FS
        .scope(fs, async {
            t.await;
        })
        .await;

    let _ = fs::remove_dir_all(data_dir_str);
}

#[allow(dead_code)]
pub async fn read_to_string(ino: u64, fs: &EncryptedFs) -> String {
    let fh = fs.open(ino, true, false).await.unwrap();
    let buf = &mut [0; 4096];
    let buf2 = vec![];
    let mut cur = Cursor::new(buf2);
    let mut read = 0;
    let mut offset = 0;
    loop {
        if read == buf.len() {
            read = 0;
        }
        let len = fs.read(ino, offset, &mut buf[read..], fh).await.unwrap();
        if len == 0 {
            fs.release(fh).await.unwrap();
            return String::from_utf8(cur.into_inner()).unwrap();
        }
        cur.write_all(&buf[read..len]).unwrap();
        read += len;
        offset += len as u64;
    }
}

#[allow(dead_code)]
pub async fn copy_all_file_range(
    fs: &EncryptedFs,
    src_ino: u64,
    src_offset: u64,
    dest_ino: u64,
    dest_offset: u64,
    size: usize,
    src_fh: u64,
    dest_fh: u64,
) {
    let mut copied = 0;
    let file_range_req = CopyFileRangeReq::builder()
        .src_ino(src_ino)
        .src_offset(src_offset)
        .dest_ino(dest_ino)
        .dest_offset(dest_offset)
        .src_fh(src_fh)
        .dest_fh(dest_fh)
        .build();
    while copied < size {
        let len = fs
            .copy_file_range(&file_range_req, size - copied)
            .await
            .unwrap();
        assert!(!(len == 0 && copied < size), "Failed to copy all bytes");
        copied += len;
    }
}

#[allow(dead_code)]
pub async fn read_exact(fs: &EncryptedFs, ino: u64, offset: u64, buf: &mut [u8], handle: u64) {
    let mut read = 0;
    while read < buf.len() {
        let len = fs
            .read(ino, offset + read as u64, &mut buf[read..], handle)
            .await
            .unwrap();
        assert!(!(len == 0 && read < buf.len()), "Failed to read all bytes");
        read += len;
    }
}

#[allow(dead_code)]
pub fn bench<F: Future + Send + Sync>(
    key: &'static str,
    worker_threads: usize,
    read_only: bool,
    f: F,
) {
    block_on(
        async {
            run_test(TestSetup { key, read_only }, f).await;
        },
        worker_threads,
    );
}

#[allow(dead_code)]
pub fn block_on<F: Future>(future: F, worker_threads: usize) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[allow(dead_code)]
pub async fn get_fs() -> Arc<EncryptedFs> {
    CURRENT_FS.with(|fs| fs.clone())
}

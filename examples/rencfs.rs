pub(crate) mod fs {
    use std::io;
    use std::io::{Error, ErrorKind, SeekFrom};
    use std::path::Path;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use futures_util::FutureExt;
    use rencfs::async_util;
    use rencfs::crypto::Cipher;
    use rencfs::encryptedfs::{
        CreateFileAttr, EncryptedFs, FileType, FsError, FsResult, PasswordProvider,
    };
    use shush_rs::SecretString;
    use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

    use crate::ROOT_CIPHER_FS_DATA_DIR;

    pub struct OpenOptions {
        create: bool,
        read: bool,
        write: bool,
    }

    impl OpenOptions {
        pub fn new() -> Self {
            OpenOptions {
                create: false,
                read: false,
                write: false,
            }
        }

        pub fn create(&mut self, create: bool) -> &mut OpenOptions {
            self.create = create;
            self
        }

        pub fn read(&mut self, read: bool) -> &mut OpenOptions {
            self.read = read;
            self
        }
        pub fn write(&mut self, write: bool) -> &mut OpenOptions {
            self.write = write;
            self
        }

        // todo: validate options
        pub async fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
            File::new(FileInit {
                create: self.create,
                read: self.read,
                write: self.write,
                path: SecretString::from_str(path.as_ref().to_path_buf().to_str().unwrap())
                    .unwrap(),
            })
            .await
            // todo: correctly map to io::Error
            .map_err(map_err)
        }
    }

    pub struct File {
        fs: Arc<EncryptedFs>,
        context: FileContext,
    }

    struct FileInit {
        create: bool,
        read: bool,
        write: bool,
        path: SecretString,
    }
    struct FileContext {
        ino: u64,
        // we need
        // to keep fh separate as if we release the write we invalidate fh and maybe we read later on
        // todo: kep fh as Option as maybe only one is needed
        fh_read: u64,
        fh_write: u64,
        pos: u64,
    }

    impl File {
        async fn new(init: FileInit) -> FsResult<Self> {
            let fs = get_fs().await?;
            let context = File::init(init, fs.clone()).await?;
            Ok(File { fs, context })
        }

        async fn init(init: FileInit, fs: Arc<EncryptedFs>) -> FsResult<FileContext> {
            // todo:
            // split path and navigate recursively to parent folder and use that as ino
            // and filename as name
            // split manually
            // and keep items in SecretString
            // so we don't leak private string in mem which are not zeroized
            // todo: set correct gid and uid like src/encryptedfs.rs:2295
            let attr = if init.create {
                let (_, attr) = fs
                    .create(1, &init.path, file_attr(), init.read, false)
                    .await?;
                attr
            } else {
                fs.find_by_name(1, &init.path)
                    .await?
                    .ok_or(FsError::NotFound(""))?
            };
            let fh_read = fs.open(attr.ino, init.read, false).await?;
            let fh_write = fs.open(attr.ino, false, init.write).await?;
            Ok(FileContext {
                ino: attr.ino,
                fh_read,
                fh_write,
                pos: 0,
            })
        }
    }

    impl AsyncRead for File {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let _desired_to_read = buf.remaining();

            // Call your own async method
            let binding = self.fs.clone();
            let async_op = binding.read(
                self.context.ino,
                self.context.pos,
                buf.initialize_unfilled(),
                self.context.fh_read,
            );

            // Convert the future into a pinned future
            let mut future = Box::pin(async_op);

            // Poll the future
            match future.poll_unpin(cx) {
                Poll::Ready(Ok(len)) => {
                    drop(future);
                    self.context.pos += len as u64;
                    buf.advance(len);
                    // todo:
                    // check how to handle the case
                    // when we cannot fill the buffer,
                    // the docs recommend to return Pending in that case
                    // if len == 0 && len < desired_to_read {
                    //     return Poll::Pending;
                    // }
                    Poll::Ready(Ok(()))
                } // Return the length of the written buffer
                Poll::Ready(Err(e)) => Poll::Ready(Err(map_err(e))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    // todo: impl AsyncReadBuf

    impl AsyncWrite for File {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, Error>> {
            // Call your own async method
            let binding = self.fs.clone();
            let async_op = binding.write(
                self.context.ino,
                self.context.pos,
                buf,
                self.context.fh_write,
            );

            // Convert the future into a pinned future
            let mut future = Box::pin(async_op);

            // Poll the future
            match future.poll_unpin(cx) {
                Poll::Ready(Ok(len)) => {
                    self.context.pos += len as u64;
                    Poll::Ready(Ok(len))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(map_err(e))),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            // Call your own async method
            let async_op = self.fs.flush(self.context.fh_write);

            // Convert the future into a pinned future
            let mut future = Box::pin(async_op);

            // Poll the future
            match future.poll_unpin(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(map_err(e))),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            // Call your own async method
            let async_op = self.fs.release(self.context.fh_write);

            // Convert the future into a pinned future
            let mut future = Box::pin(async_op);

            // Poll the future
            match future.poll_unpin(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(map_err(e))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncSeek for File {
        fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
            let attr = async_util::call_async(async {
                self.fs.get_attr(self.context.ino).await.map_err(map_err)
            })?;

            let new_pos = match position {
                SeekFrom::Start(pos) => pos as i64,
                SeekFrom::End(pos) => attr.size as i64 + pos,
                SeekFrom::Current(pos) => self.context.pos as i64 + pos,
            };
            if new_pos < 0 {
                return Err(io::Error::new(ErrorKind::InvalidInput, "position < 0"));
            }
            if new_pos > attr.size as i64 {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "position after file size",
                ));
            }

            self.context.pos = new_pos as u64;
            Ok(())
        }

        fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
            Poll::Ready(Ok(self.context.pos))
        }
    }

    struct PasswordProviderImpl {}

    impl PasswordProvider for PasswordProviderImpl {
        fn get_password(&self) -> Option<SecretString> {
            Some(SecretString::from_str("pass42").unwrap())
        }
    }

    async fn get_fs() -> FsResult<Arc<EncryptedFs>> {
        EncryptedFs::new(
            Path::new(ROOT_CIPHER_FS_DATA_DIR).to_path_buf(),
            Box::new(PasswordProviderImpl {}),
            Cipher::ChaCha20Poly1305,
            false,
        )
        .await
    }

    const fn file_attr() -> CreateFileAttr {
        CreateFileAttr {
            kind: FileType::RegularFile,
            perm: 0o644,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        }
    }

    fn map_err(err: FsError) -> Error {
        Error::new(ErrorKind::Other, anyhow::Error::from(err))
    }
}

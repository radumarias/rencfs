# Ramp-up guide

2. Become familiar with the [basic concepts and features](https://github.com/xoriors/rencfs?tab=readme-ov-file#-rencfs) and [lib docs](https://docs.rs/rencfs/latest/rencfs).
3. Understand the [layers](https://github.com/xoriors/rencfs/blob/main/website/resources/layers.png).
4. Detailed [sequence flows](flows.md).
5. Give it a [quick try](https://github.com/xoriors/rencfs#give-it-a-quick-try-with-docker) with Docker.
6. Or run it as [CLI app](https://github.com/xoriors/rencfs?tab=readme-ov-file#command-line-tool).
7. Clone or fork the repo. After being added to it, you can work in your branches in the original repo. No need to fork it if you don't want to
8. [Build](https://github.com/xoriors/rencfs?tab=readme-ov-file#build-from-source) from source and start it. If you don't have Linux, you can [develop inside a container](https://github.com/xoriors/rencfs?tab=readme-ov-file#developing-inside-a-container).
    This will start a new Linux container and remotely connecting the local IDE to the container, you can also connect with the IDE's terminal to it, run and debug the code. On Windows, you can use [WSL](https://harsimranmaan.medium.com/install-and-setup-rust-development-environment-on-wsl2-dccb4bf63700).
    As a last resort, you can [develop in browser](https://github.com/xoriors/rencfs/blob/main/README.md#browser).
9. Run and understand the [examples](../../examples). You can write some new ones to understand the flow and code better. If you do, please create a `PR` back to the parent repo targeting the `main` branch to include those for others too.
10. Become familiar with [tests](../src/encryptedfs/test.rs) (and in other files) and [benchmarks](../benches). You can write some new ones to better understand the flow and code better. If you do, please create a `PR` back to the parent repo targeting the `main` branch to include those for others too.

# Testing

We'd appreciate it if you could help test the app. For now, the filesystem mounting works only on Linux, so the cleanest way is to test on Linux.

Here are some ways you can do it.

## Testing in the browser or local VSCode

You'll need a GitHub account for this.

This will create a Codespace instance on GitHub, which is a Linux container, so we will be able to test it.  
The instance config is 2 CPUs and 4 GB RAM. You have 120 CPU hours per month free for Codespace, which means 60 hours for that instance. We will connect to it from the browser and the local VSCode.

### First setup

1. Open the [repo](https://github.com/radumarias/rencfs)
2. Press `Code` button  
  ![image](https://github.com/user-attachments/assets/7c0e8872-fe1f-44b9-a833-2586ade4f618)
3. Create codespace on main
  ![image](https://github.com/user-attachments/assets/5fee55f6-ef54-427c-b790-c135312d3355)
4. This will create the container on GitHub. If it asks you to setup config, select the minimum possible CPU and RAM
5. Start it and leave it to finish. This could take a bit longer
6. Goto terminal in the browser version of the VSCode editor you're presented with. It should be at the bottom, or open it from the menu `Terminal -> New Terminal`
7. You can find the menu in the top left, with 3 lines icon
  ![image](https://github.com/user-attachments/assets/48681023-e450-49b3-8526-ec0323be0d40)
8. Install Rust and create a `tmp` folder, which we will use to copy files from our machine, by typing these in terminal:
  ```bash
  apt-get update && apt-get install fuse3
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  mkdir tmp && mkdir mnt && mkdir data
  ```
  Press enter on Rust installation, accepting all defaults
  
### Each resume and after the first setup

1. Open the [repo](https://github.com/radumarias/rencfs)
2. Press `Code` button  
  ![image](https://github.com/user-attachments/assets/7c0e8872-fe1f-44b9-a833-2586ade4f618)
3. Press ```...``` right to the instance in the list
  ![image](https://github.com/user-attachments/assets/c621c258-009d-46bf-adb7-f81a3d7131f6)

#### VSCode in Browser

4. Press `Open in Browser`, or directly click on the container name

#### In local VSCode

Make sure you have VSCode installed locally, based on your OS.

4. Press `Open in Visual Studio Code`

#### Continue

Do step 11 from above.

5. Type this in the VSCode terminal, which will fetch the changes from the repo (if there are conflicts, accept Theirs):
  ```bash
  git pull
  git checkout --theirs .
  cargo run --release -- mount -m mnt -d data
  ```
6. Input a password and confirm it the first time
9. Copy test files from your machine to `tmp` folder in `VSCode`, by `Ctrl + C / Ctrl + V` or by Drag and Drop
10. Copy files and folders from `tmp` to `mnt` and do all kinds of operations on `nnt` folder
11. Make sure files were copied successfully by right-clicking a file and then `Download...` and save it to local machine
12. Make sure files open correctly
13. Do all kinds of operations in `mnt` folder and make sure they are ok

- [ ] Testing on Linux
- [ ] Testing on macOS
- [ ] Testing on Windows

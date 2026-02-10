# ClicBot Dev Tools  
**User Manual (Basic Usage)**

ClicBot Dev Tools is a Windows desktop application that allows you to **control, program, and test** ClicBot robots in a simple and direct way.

This manual explains **how to use the application**, without technical details.

---

## 1. Starting the Application

1. Download the latest version from the **Releases** section
2. Run `ClicBot_tools.exe`
3. The main window will appear

> ℹ️ Windows may show a security warning the first time you run the app. Confirm to continue.

---

## 2. Connecting to the Robot

### Steps

1. Enter the robot **IP address**
2. Check the **port** (usually already set)
3. Click **Connect**

If the connection is successful, status messages will appear in the log area.

---

## 3. Assembly Mode (Module Detection)

**Assembly Mode** is used to:
- detect the modules connected to the robot
- enable correct movement programming

### How to use it

1. With the robot connected, click **Assembly**
2. Wait a few seconds
3. The robot modules will be detected automatically

---

## 4. Joystick Control (Drive Mode)

The application allows you to **drive the robot in real time** using a controller.

### Enable drive mode

1. Open **Joystick & Programming**
2. Click **Enable Drive**
3. Use the joystick to move the robot

### Disable drive mode

- Click **Disable Drive** before closing the window

---

## 5. Programming Directions

You can teach the robot how to move in the main directions:

- Rest  
- Forward  
- Left  
- Right  

### Procedure

1. Open **Joystick & Programming**
2. Click the direction you want to program
3. Move the robot as desired
4. Confirm when prompted

The movement is saved automatically.

---

## 6. Animation Studio (Movements & Animations)

**Animation Studio** lets you create custom movement sequences.

### Main features

- Create new movements
- Add poses
- Adjust timing
- Test movements on the robot

### Quick start

1. Open **Animation Studio**
2. Create a new animation
3. Use **Capture Pose** to save a position
4. Press **Play** to test it on the robot

---

## 7. Uploading ZIP Projects

You can upload ZIP projects to the robot and run them directly.

### Steps

1. Click **Upload ZIP**
2. Select the `.zip` file
3. Wait for the upload to complete
4. Use **Play** / **Stop** to start or stop the project

---

## 8. WebSocket Bridge (Optional)

The WebSocket Bridge allows the app to connect with external tools.

For normal use, this feature is **not required**.

---

## 9. SSH Tool (First-time setup and usage)

The **SSH Tool** allows secure access to the robot for advanced features and maintenance.

⚠️ **Important**
- **Public key injection is required only once**
- **SSH must be re-enabled after every robot reboot**, if SSH access is needed

---

### Overview: how SSH works in ClicBot Dev Tools

There are **two different steps**:

**First time only**
- Generate a public key file (`.pub`)
- Upload `enabler.zip` to the robot
- Inject the public key

**Every time the robot is restarted**
- Upload `enabler.zip`
- Enable SSH

---

## First-time setup (required only once)

### Step 1 – Generate the public key file

On **Windows**:

1. Press **Win + R**, type `cmd`, then press **Enter**
2. In the command prompt, type:

ssh-keygen

3. When asked:
   - **File location** → press **Enter** (default is fine)
   - **Passphrase** → press **Enter** (leave empty)

4. Two files will be created automatically:
   - `id_rsa` → **private key** (keep this file safe on your PC)
   - `id_rsa.pub` → **public key**

5. Rename the public key file:

id_rsa.pub → publickey.pub

This file will be used only for SSH activation.

---

### Step 2 – Upload `enabler.zip` to the robot

1. In **ClicBot Dev Tools**, click **Upload ZIP**
2. Select `enabler.zip`
3. Start the application on the robot (**Play**)

This prepares the robot for SSH activation.

---

### Step 3 – Inject the public key (one time only)

1. Open **SSH Tool**
2. Load the file `publickey.pub`
3. Click **Inject Public Key**

✅ The public key is now stored on the robot  
❗ This step will **not** be required again

---

## Enabling SSH (required after every robot reboot)

Each time the robot is restarted, SSH must be enabled again if you need it.

### Steps

1. Upload `enabler.zip` to the robot
2. Start the application on the robot
3. Open **SSH Tool**
4. Click **Enable SSH**

✅ SSH is now active

> ℹ️ If SSH is not needed, this step can be skipped.

---

## Connecting to the robot via SSH (from PC)

To connect to the robot via SSH, the **private key must be available on your PC**.

Example command:

ssh -i clicbot_key root@IP_CLICBOT

## Important notes

- Public key injection is required **only once**
- SSH must be enabled **after every robot reboot**
- The private key (`id_rsa`) must be kept safe on your PC
- Do not delete the public key file after setup
- SSH access is optional and only required when needed

---

## 10. Common Troubleshooting

### The robot does not connect
- Make sure the PC and the robot are on the same network
- Check the IP address and port
- Restart the robot and the application

### The joystick does not work
- Make sure the controller is connected before starting the application
- Try restarting the application

### Movements are not saved
- Make sure **Assembly Mode** has been completed
- Repeat the programming procedure

---

## 11. Support

To report issues or suggest improvements:
- use the **Issues** tab on GitHub

---

## Final Notes

- The application is under continuous development
- Some features may change or improve over time
- The EXE requires an **activation key** for full functionality

Thank you for using **ClicBot Dev Tools** 🚀

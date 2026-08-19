# 🔒 E2E Encrypted P2P Chat & File Transfer App

A secure, lightweight Peer-to-Peer (P2P) desktop application for real-time messaging and file sharing. Built with **Python**, **Tkinter**, and **Hybrid Cryptography (RSA-2048 + AES-256)**, ensuring completely decentralized and end-to-end encrypted communication. And here, you can communicate with the other person using messages, photos, videos, or other types of files.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Security](https://img.shields.io/badge/Encryption-RSA--2048%20%2B%20AES--256-brightgreen)
![GUI](https://img.shields.io/badge/UI-Tkinter-orange)

---

## ✨ Features

- 🔐 **End-to-End Encryption (E2EE):** 
  - **RSA-2048:** Secure public/private key exchange during connection setup.
  - **AES-256 (CBC mode):** Fast symmetric encryption for chat messages and binary file transfers.
- 🌐 **Decentralized P2P Architecture:** No central server required. Each node acts as both a server (listener) and a client.
- 📁 **Encrypted File Transfer:** Send any file type securely over the socket connection. Files are automatically decrypted and saved into a local `downloads/` directory.
- 🎨 **Modern Blue-Themed GUI:** Built with Python `Tkinter` featuring custom rounded canvas buttons and chat history tracking.
- 📜 **Connection History:** Saves recent peer addresses (`ip:port`) in a local JSON config file for quick reconnects.

---

## 🛠️ Architecture & Security Model

1. **Handshake (Key Exchange):**
   - Peer A connects to Peer B.
   - Peer B sends its **RSA-2048 Public Key (PEM format)** to Peer A.
   - Peer A responds with its own **RSA-2048 Public Key**.
2. **Message / File Encryption:**
   - A unique 256-bit **AES Key** and **IV** are generated per payload.
   - Payload is encrypted with **AES-256-CBC** (PKCS7 padded).
   - The AES key itself is encrypted using the recipient's **RSA Public Key** (`OAEP` padding with `SHA256`).
3. **Decryption:**
   - Recipient decrypts the AES key using their **RSA Private Key**, then decrypts the actual payload using the AES key.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- `cryptography` library

### Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/Ductacco/p2p-e2e-chat-app.git](https://github.com/Ductacco/p2p-e2e-chat-app.git)
   cd p2p-e2e-chat-app

### 💻How to Run & Test
#### Option 1: Testing Locally (Single Machine)
Run two separate terminal instances on different ports to test on a single computer:

Terminal 1 (Node A - Port 5000):

Bash
python p2p_app.py --port 5000
Click Start Server (Listens on port 5000).

Terminal 2 (Node B - Port 5001):

Bash
python p2p_app.py --port 5001
Click Start Server (Listens on port 5001).

In Peer (ip:port) field, type: 127.0.0.1:5000

Click Connect.

#### Option 2: Connecting Two Devices in the Same LAN
To connect two different computers connected to the same Wi-Fi or Ethernet network:

Find Local IPv4 Address (Host Machine):

Windows: Open CMD and run ipconfig. Look for IPv4 Address (e.g., 192.168.1.15).

Linux / macOS: Open Terminal and run ip a or ifconfig.

Start Server on Host Machine:

Run python p2p_app.py --port 5000 and click Start Server.

Connect from Client Machine:

Run the application on the second device.

Type the Host Machine's IP and port in Peer (ip:port) (e.g., 192.168.1.15:5000).

Click Connect.

⚠️ Firewall Note: Ensure your host firewall (e.g., Windows Defender Firewall) permits inbound connections on port 5000

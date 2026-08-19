#!/usr/bin/env python3
"""
p2p_app.py - Blue themed UI with rounded buttons + E2E Encryption

Simple P2P chat + file transfer demo with RSA + AES encryption.

Usage:
    python p2p_app.py --port 5000
Run multiple instances (different ports) to test locally.
"""
import socket
import threading
import argparse
import json
import struct
import os
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Encryption utilities ---
class CryptoManager:
    def __init__(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.peer_public_key = None
        
    def get_public_key_pem(self):
        """Get public key as PEM string"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def set_peer_public_key(self, pem_string):
        """Set peer's public key from PEM string"""
        self.peer_public_key = serialization.load_pem_public_key(
            pem_string.encode('utf-8'),
            backend=default_backend()
        )
    
    def encrypt_message(self, plaintext):
        """Encrypt message using AES-256, encrypt AES key with RSA"""
        if not self.peer_public_key:
            raise ValueError("Peer public key not set")
        
        # Generate random AES key and IV
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)
        
        # Encrypt plaintext with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad plaintext to AES block size
        plaintext_bytes = plaintext.encode('utf-8')
        padding_length = 16 - (len(plaintext_bytes) % 16)
        padded_plaintext = plaintext_bytes + bytes([padding_length] * padding_length)
        
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        encrypted_key = self.peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return base64 encoded components
        return {
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    
    def decrypt_message(self, encrypted_data):
        """Decrypt message using RSA and AES"""
        # Decrypt AES key with RSA
        encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt ciphertext with AES
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext.decode('utf-8')
    
    def encrypt_file(self, file_data):
        """Encrypt file data using AES-256"""
        if not self.peer_public_key:
            raise ValueError("Peer public key not set")
        
        # Generate random AES key and IV
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        
        # Encrypt file data with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad file data
        padding_length = 16 - (len(file_data) % 16)
        padded_data = file_data + bytes([padding_length] * padding_length)
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        encrypted_key = self.peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    
    def decrypt_file(self, encrypted_data):
        """Decrypt file data"""
        # Decrypt AES key
        encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt file data
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_data[-1]
        file_data = padded_data[:-padding_length]
        
        return file_data

# --- Networking utilities ---
HEADER_LEN_PACK = "!I"

def send_message(sock: socket.socket, header: dict, payload: bytes = b""):
    header_bytes = json.dumps(header).encode('utf-8')
    sock.sendall(struct.pack(HEADER_LEN_PACK, len(header_bytes)))
    sock.sendall(header_bytes)
    if payload:
        sock.sendall(payload)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed while reading")
        buf += chunk
    return buf

def recv_message(sock: socket.socket):
    header_len_bytes = recv_exact(sock, 4)
    (header_len,) = struct.unpack(HEADER_LEN_PACK, header_len_bytes)
    header_bytes = recv_exact(sock, header_len)
    header = json.loads(header_bytes.decode('utf-8'))
    payload = None
    if header.get('payload_len'):
        payload = recv_exact(sock, header['payload_len'])
    return header, payload

# --- P2P server thread ---
class PeerServer(threading.Thread):
    def __init__(self, host, port, on_peer_message, crypto_manager):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.on_peer_message = on_peer_message
        self.crypto_manager = crypto_manager
        self.sock = None
        self.running = threading.Event()
        self.peer_crypto = {}  # Store crypto manager for each peer

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.running.set()
        print(f"[Server] Listening on {self.host}:{self.port}")
        try:
            while self.running.is_set():
                try:
                    conn, addr = self.sock.accept()
                    print(f"[Server] Accepted {addr}")
                    handler = threading.Thread(target=self.handle_peer, args=(conn, addr), daemon=True)
                    handler.start()
                except OSError:
                    break
        finally:
            if self.sock:
                self.sock.close()

    def stop(self):
        self.running.clear()
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def handle_peer(self, conn: socket.socket, addr):
        peer_id = f"{addr[0]}:{addr[1]}"
        peer_crypto = CryptoManager()
        
        try:
            # Key exchange: send public key
            header = {'type': 'key_exchange', 'public_key': peer_crypto.get_public_key_pem()}
            send_message(conn, header)
            
            # Receive peer's public key
            header, _ = recv_message(conn)
            if header.get('type') == 'key_exchange':
                peer_crypto.set_peer_public_key(header['public_key'])
                self.on_peer_message('system', peer_id, 'Key exchange completed (server)', None)
            
            while True:
                header, payload = recv_message(conn)
                msg_type = header.get('type')
                
                if msg_type == 'chat':
                    # Decrypt message
                    encrypted_data = header.get('encrypted_data')
                    text = peer_crypto.decrypt_message(encrypted_data)
                    self.on_peer_message('chat', peer_id, text, None)
                    
                elif msg_type == 'file':
                    # Decrypt file
                    filename = header.get('filename', 'unnamed')
                    encrypted_data = header.get('encrypted_data')
                    file_data = peer_crypto.decrypt_file(encrypted_data)
                    
                    downloads = os.path.join(os.getcwd(), "downloads")
                    os.makedirs(downloads, exist_ok=True)
                    save_path = os.path.join(downloads, os.path.basename(filename))
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                    self.on_peer_message('file', peer_id, save_path, len(file_data))
                else:
                    print("[Server] Unknown message type:", msg_type)
        except ConnectionError:
            print(f"[Server] Connection to {peer_id} closed")
        except Exception as e:
            print(f"[Server] Error handling peer {peer_id}: {e}")
        finally:
            try:
                conn.close()
            except:
                pass

# --- P2P client connection ---
class PeerConnection:
    def __init__(self, host, port, on_remote_msg, crypto_manager):
        self.host = host
        self.port = port
        self.on_remote_msg = on_remote_msg
        self.crypto_manager = crypto_manager
        self.sock = None
        self.listener = None

    def connect(self, timeout=5):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(None)
        
        # Key exchange: receive server's public key first
        header, _ = recv_message(self.sock)
        if header.get('type') == 'key_exchange':
            self.crypto_manager.set_peer_public_key(header['public_key'])
        
        # Send our public key
        header = {'type': 'key_exchange', 'public_key': self.crypto_manager.get_public_key_pem()}
        send_message(self.sock, header)
        
        peer_id = f"{self.host}:{self.port}"
        self.on_remote_msg('system', peer_id, 'Key exchange completed (client)')
        
        self.listener = threading.Thread(target=self._listen_loop, args=(peer_id,), daemon=True)
        self.listener.start()
        return True

    def _listen_loop(self, peer_id):
        try:
            while True:
                header, payload = recv_message(self.sock)
                msg_type = header.get('type')
                
                if msg_type == 'chat':
                    # Decrypt message
                    encrypted_data = header.get('encrypted_data')
                    text = self.crypto_manager.decrypt_message(encrypted_data)
                    self.on_remote_msg('chat', peer_id, text)
                    
                elif msg_type == 'file':
                    # Decrypt file
                    filename = header.get('filename', 'unnamed')
                    encrypted_data = header.get('encrypted_data')
                    file_data = self.crypto_manager.decrypt_file(encrypted_data)
                    
                    downloads = os.path.join(os.getcwd(), "downloads")
                    os.makedirs(downloads, exist_ok=True)
                    save_path = os.path.join(downloads, os.path.basename(filename))
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                    self.on_remote_msg('file', peer_id, save_path)
                else:
                    print("[Client] Unknown msg type", msg_type)
        except ConnectionError:
            print(f"[Client] Connection closed by peer {peer_id}")
        except Exception as e:
            print(f"[Client] Error in listen loop: {e}")
        finally:
            try:
                self.sock.close()
            except:
                pass

    def send_chat(self, text):
        # Encrypt message
        encrypted_data = self.crypto_manager.encrypt_message(text)
        header = {'type': 'chat', 'encrypted_data': encrypted_data}
        send_message(self.sock, header)

    def send_file(self, filepath):
        fname = os.path.basename(filepath)
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Encrypt file
        encrypted_data = self.crypto_manager.encrypt_file(data)
        header = {'type': 'file', 'filename': fname, 'encrypted_data': encrypted_data}
        send_message(self.sock, header)

    def close(self):
        try:
            self.sock.close()
        except:
            pass

# --- Custom Round Button ---
class RoundButton(tk.Canvas):
    def __init__(self, parent, text, command=None, bg_color="#2196F3", hover_color="#1976D2", 
                 text_color="white", width=100, height=35, **kwargs):
        super().__init__(parent, width=width, height=height, bg=parent['bg'], 
                        highlightthickness=0, **kwargs)
        self.command = command
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.text_color = text_color
        self.width = width
        self.height = height
        self.text = text
        self.disabled = False
        
        self.draw_button()
        self.bind("<Button-1>", self.on_click)
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
    
    def draw_button(self, hover=False):
        self.delete("all")
        color = self.hover_color if hover and not self.disabled else self.bg_color
        if self.disabled:
            color = "#B0BEC5"
        
        # Draw rounded rectangle
        radius = self.height // 2
        self.create_oval(0, 0, self.height, self.height, fill=color, outline="")
        self.create_oval(self.width - self.height, 0, self.width, self.height, fill=color, outline="")
        self.create_rectangle(radius, 0, self.width - radius, self.height, fill=color, outline="")
        
        # Draw text
        text_color = "#90A4AE" if self.disabled else self.text_color
        self.create_text(self.width // 2, self.height // 2, text=self.text, 
                        fill=text_color, font=("Arial", 10, "bold"))
    
    def on_click(self, event):
        if not self.disabled and self.command:
            self.command()
    
    def on_enter(self, event):
        if not self.disabled:
            self.draw_button(hover=True)
    
    def on_leave(self, event):
        self.draw_button(hover=False)
    
    def config(self, **kwargs):
        if 'state' in kwargs:
            self.disabled = (kwargs['state'] == tk.DISABLED)
            self.draw_button()

# --- Connection History Manager ---
class ConnectionHistory:
    def __init__(self, filename="peer_history.json"):
        self.filename = filename
        self.connections = []
        self.load()
    
    def load(self):
        try:
            if os.path.exists(self.filename):
                with open(self.filename, 'r') as f:
                    data = json.load(f)
                    self.connections = data.get('connections', [])
        except Exception as e:
            print(f"Error loading history: {e}")
            self.connections = []
    
    def save(self):
        try:
            with open(self.filename, 'w') as f:
                json.dump({'connections': self.connections}, f, indent=2)
        except Exception as e:
            print(f"Error saving history: {e}")
    
    def add(self, peer_address):
        if peer_address in self.connections:
            self.connections.remove(peer_address)
        self.connections.insert(0, peer_address)
        self.connections = self.connections[:10]
        self.save()
    
    def get_all(self):
        return self.connections
    
    def remove(self, peer_address):
        if peer_address in self.connections:
            self.connections.remove(peer_address)
            self.save()

# --- GUI ---
class P2PApp:
    def __init__(self, master, local_host='0.0.0.0', local_port=5000):
        self.master = master
        master.title("P2P Chat App (E2E Encrypted)")
        self.local_host = local_host
        self.local_port = local_port
        
        # Color scheme
        BG_COLOR = "#E3F2FD"
        FRAME_BG = "#BBDEFB"
        CHAT_BG = "#FFFFFF"
        
        master.configure(bg=BG_COLOR)

        # Top frame: server control
        frame_top = tk.Frame(master, bg=FRAME_BG, padx=10, pady=10)
        frame_top.pack(fill=tk.X, padx=8, pady=8)
        
        tk.Label(frame_top, text="Local Port:", bg=FRAME_BG, fg="#0D47A1", 
                font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.port_var = tk.IntVar(value=self.local_port)
        port_entry = tk.Entry(frame_top, textvariable=self.port_var, width=8, 
                             font=("Arial", 10), relief=tk.FLAT, bg="white")
        port_entry.pack(side=tk.LEFT, padx=5)
        
        self.start_btn = RoundButton(frame_top, "Start Server", command=self.start_server,
                                    bg_color="#4CAF50", hover_color="#45a049")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = RoundButton(frame_top, "Stop Server", command=self.stop_server,
                                   bg_color="#F44336", hover_color="#da190b")
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn.config(state=tk.DISABLED)
        
        # Encryption indicator
        tk.Label(frame_top, text="🔒 E2E Encrypted", bg=FRAME_BG, fg="#4CAF50", 
                font=("Arial", 9, "bold")).pack(side=tk.RIGHT, padx=10)

        # Chat display
        chat_frame = tk.Frame(master, bg=BG_COLOR)
        chat_frame.pack(padx=8, pady=8, fill=tk.BOTH, expand=True)
        
        self.chat = scrolledtext.ScrolledText(chat_frame, state='disabled', wrap=tk.WORD, 
                                              width=60, height=20, font=("Arial", 10),
                                              bg=CHAT_BG, fg="#212121", relief=tk.FLAT,
                                              borderwidth=2)
        self.chat.pack(fill=tk.BOTH, expand=True)

        # Peer connect frame
        frame_conn = tk.Frame(master, bg=FRAME_BG, padx=10, pady=10)
        frame_conn.pack(fill=tk.X, padx=8, pady=8)
        
        tk.Label(frame_conn, text="Peer (ip:port):", bg=FRAME_BG, fg="#0D47A1",
                font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        
        self.peer_entry = ttk.Combobox(frame_conn, width=18, font=("Arial", 10))
        self.peer_entry.pack(side=tk.LEFT, padx=5)
        
        self.connect_btn = RoundButton(frame_conn, "Connect", command=self.connect_peer,
                                      bg_color="#2196F3", hover_color="#1976D2")
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = RoundButton(frame_conn, "Disconnect", command=self.disconnect_peer,
                                         bg_color="#FF9800", hover_color="#F57C00")
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        self.disconnect_btn.config(state=tk.DISABLED)
        
        self.clear_history_btn = RoundButton(frame_conn, "Clear History", 
                                            command=self.clear_history,
                                            bg_color="#607D8B", hover_color="#455A64",
                                            width=110)
        self.clear_history_btn.pack(side=tk.LEFT, padx=5)

        # Message entry
        frame_msg = tk.Frame(master, bg=FRAME_BG, padx=10, pady=10)
        frame_msg.pack(fill=tk.X, padx=8, pady=8)
        
        self.msg_entry = tk.Entry(frame_msg, width=40, font=("Arial", 10), 
                                 relief=tk.FLAT, bg="white")
        self.msg_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        self.send_btn = RoundButton(frame_msg, "Send", command=self.send_message,
                                   bg_color="#2196F3", hover_color="#1976D2", width=80)
        self.send_btn.pack(side=tk.LEFT, padx=5)
        self.send_btn.config(state=tk.DISABLED)
        
        self.file_btn = RoundButton(frame_msg, "Send File", command=self.send_file,
                                   bg_color="#9C27B0", hover_color="#7B1FA2")
        self.file_btn.pack(side=tk.LEFT, padx=5)
        self.file_btn.config(state=tk.DISABLED)

        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        
        # Files received frame
        frame_files = tk.Frame(master, bg=FRAME_BG, padx=10, pady=10)
        frame_files.pack(fill=tk.BOTH, padx=8, pady=8, expand=False)
        
        tk.Label(frame_files, text="Received Files:", bg=FRAME_BG, fg="#0D47A1",
                font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        
        files_inner = tk.Frame(frame_files, bg=FRAME_BG)
        files_inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.files_listbox = tk.Listbox(files_inner, height=4, font=("Arial", 9),
                                        bg="white", relief=tk.FLAT, selectmode=tk.SINGLE)
        self.files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(files_inner, command=self.files_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.files_listbox.config(yscrollcommand=scrollbar.set)
        
        file_btns = tk.Frame(frame_files, bg=FRAME_BG)
        file_btns.pack(side=tk.LEFT, padx=5)
        
        self.open_file_btn = RoundButton(file_btns, "Open File", command=self.open_selected_file,
                                        bg_color="#4CAF50", hover_color="#45a049", width=100)
        self.open_file_btn.pack(pady=2)
        
        self.open_folder_btn = RoundButton(file_btns, "Open Folder", command=self.open_downloads_folder,
                                          bg_color="#2196F3", hover_color="#1976D2", width=100)
        self.open_folder_btn.pack(pady=2)
        
        self.clear_files_btn = RoundButton(file_btns, "Clear List", command=self.clear_files_list,
                                          bg_color="#607D8B", hover_color="#455A64", width=100)
        self.clear_files_btn.pack(pady=2)

        # internal
        self.crypto = CryptoManager()
        self.server = None
        self.peer_conn = None
        self.server_running = False
        self.history = ConnectionHistory()
        self.received_files = []

        # Menu
        menubar = tk.Menu(master)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=helpmenu)
        master.config(menu=menubar)
        
        self.update_history_dropdown()
        self.append_chat("[SYSTEM] E2E Encryption enabled - All messages and files are encrypted\n", "system")

    def start_server(self):
        port = int(self.port_var.get())
        self.server = PeerServer(host=self.local_host, port=port, 
                                on_peer_message=self.on_server_msg,
                                crypto_manager=self.crypto)
        self.server.start()
        self.server_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.append_chat("[SYSTEM] Server started on port %d\n" % port, "system")

    def stop_server(self):
        if self.server:
            self.server.stop()
            self.server = None
        self.server_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.append_chat("[SYSTEM] Server stopped\n", "system")

    def on_server_msg(self, kind, peer_id, content, extra=None):
        if kind == 'chat':
            self.master.after(0, lambda: self.append_chat(f"[{peer_id}] {content}\n", "peer"))
        elif kind == 'file':
            path = content
            self.master.after(0, lambda: self.add_received_file(path, peer_id))
        elif kind == 'system':
            self.master.after(0, lambda: self.append_chat(f"[SYSTEM] {content}\n", "system"))

    def connect_peer(self):
        text = self.peer_entry.get().strip()
        if ':' not in text:
            messagebox.showerror("Error", "Peer must be ip:port")
            return
        host, port_s = text.split(':', 1)
        try:
            port = int(port_s)
        except:
            messagebox.showerror("Error", "Invalid port")
            return
        
        # Create new crypto manager for this connection
        self.crypto = CryptoManager()
        self.peer_conn = PeerConnection(host, port, on_remote_msg=self.on_remote_msg,
                                       crypto_manager=self.crypto)
        try:
            self.peer_conn.connect()
        except Exception as e:
            messagebox.showerror("Connect failed", str(e))
            self.peer_conn = None
            return
        
        self.history.add(text)
        self.update_history_dropdown()
        
        self.append_chat(f"[SYSTEM] Connected to {host}:{port}\n", "system")
        self.connect_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.NORMAL)
        self.send_btn.config(state=tk.NORMAL)
        self.file_btn.config(state=tk.NORMAL)

    def disconnect_peer(self):
        if self.peer_conn:
            try:
                self.peer_conn.close()
            except:
                pass
            self.peer_conn = None
        self.append_chat("[SYSTEM] Disconnected\n", "system")
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        self.file_btn.config(state=tk.DISABLED)

    def on_remote_msg(self, kind, peer_id, content):
        if kind == 'chat':
            self.master.after(0, lambda: self.append_chat(f"[{peer_id}] {content}\n", "peer"))
        elif kind == 'file':
            self.master.after(0, lambda: self.add_received_file(content, peer_id))
        elif kind == 'system':
            self.master.after(0, lambda: self.append_chat(f"[SYSTEM] {content}\n", "system"))

    def send_message(self):
        text = self.msg_entry.get().strip()
        if not text:
            return
        if not self.peer_conn:
            messagebox.showwarning("Not connected", "No peer connected")
            return
        try:
            self.peer_conn.send_chat(text)
            self.append_chat(f"[Me -> {self.peer_conn.host}:{self.peer_conn.port}] {text}\n", "me")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send failed", str(e))

    def send_file(self):
        if not self.peer_conn:
            messagebox.showwarning("Not connected", "No peer connected")
            return
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        try:
            self.append_chat(f"[SYSTEM] Sending encrypted file {os.path.basename(filepath)} ...\n", "system")
            self.peer_conn.send_file(filepath)
            self.append_chat(f"[Me] sent file {os.path.basename(filepath)}\n", "file")
        except Exception as e:
            messagebox.showerror("Send file failed", str(e))

    def append_chat(self, text, tag="normal"):
        self.chat.config(state='normal')
        self.chat.insert(tk.END, text, tag)
        
        self.chat.tag_config("system", foreground="#1976D2", font=("Arial", 10, "bold"))
        self.chat.tag_config("peer", foreground="#388E3C")
        self.chat.tag_config("me", foreground="#0277BD")
        self.chat.tag_config("file", foreground="#7B1FA2")
        
        self.chat.see(tk.END)
        self.chat.config(state='disabled')

    def show_about(self):
        messagebox.showinfo("About", 
            "Simple P2P Chat App with E2E Encryption\n\n"
            "Features:\n"
            "• Chat + File transfer\n"
            "• RSA-2048 key exchange\n"
            "• AES-256 encryption\n"
            "• Protection against MITM attacks\n\n"
            "Blue themed UI")
    
    def update_history_dropdown(self):
        history_list = self.history.get_all()
        self.peer_entry['values'] = history_list
    
    def clear_history(self):
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all connection history?"):
            self.history.connections = []
            self.history.save()
            self.update_history_dropdown()
            self.peer_entry.set('')
            self.append_chat("[SYSTEM] Connection history cleared\n", "system")
    
    def add_received_file(self, filepath, peer_id):
        self.received_files.append(filepath)
        filename = os.path.basename(filepath)
        self.files_listbox.insert(tk.END, f"{filename} (from {peer_id})")
        self.append_chat(f"[{peer_id}] sent encrypted file: {filename}\n", "file")
        self.files_listbox.see(tk.END)
    
    def open_selected_file(self):
        selection = self.files_listbox.curselection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a file to open")
            return
        
        index = selection[0]
        if index < len(self.received_files):
            filepath = self.received_files[index]
            if os.path.exists(filepath):
                try:
                    import platform
                    if platform.system() == 'Windows':
                        os.startfile(filepath)
                    elif platform.system() == 'Darwin':
                        os.system(f'open "{filepath}"')
                    else:
                        os.system(f'xdg-open "{filepath}"')
                    self.append_chat(f"[SYSTEM] Opened file: {os.path.basename(filepath)}\n", "system")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not open file: {e}")
            else:
                messagebox.showerror("Error", "File not found")
    
    def open_downloads_folder(self):
        downloads = os.path.join(os.getcwd(), "downloads")
        if not os.path.exists(downloads):
            messagebox.showinfo("Info", "No files have been received yet")
            return
        
        try:
            import platform
            if platform.system() == 'Windows':
                os.startfile(downloads)
            elif platform.system() == 'Darwin':
                os.system(f'open "{downloads}"')
            else:
                os.system(f'xdg-open "{downloads}"')
            self.append_chat("[SYSTEM] Opened downloads folder\n", "system")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {e}")
    
    def clear_files_list(self):
        if self.files_listbox.size() == 0:
            return
        if messagebox.askyesno("Clear List", "Clear the received files list?\n(Files will remain in downloads folder)"):
            self.files_listbox.delete(0, tk.END)
            self.received_files = []
            self.append_chat("[SYSTEM] Files list cleared\n", "system")

    def on_close(self):
        try:
            if self.server:
                self.server.stop()
        except:
            pass
        try:
            if self.peer_conn:
                self.peer_conn.close()
        except:
            pass
        self.master.destroy()

# --- main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000, help='local listening port')
    args = parser.parse_args()

    root = tk.Tk()
    app = P2PApp(root, local_host='0.0.0.0', local_port=args.port)
    app.port_var.set(args.port)

    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

if __name__ == "__main__":
    main()

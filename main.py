import os
import random
import subprocess
import json
import sys

import pyodbc
from hashlib import sha256
from getpass import getpass
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QPushButton, QApplication, QLabel,
                             QDesktopWidget, QHBoxLayout, QListWidgetItem, QSplitter, QListWidget, QFileDialog,
                             QLineEdit, QProgressBar, QDialog, QCheckBox, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QPixmap, QPalette, QBrush, QIcon
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import platform
import time
import base64
import secrets
import requests

def install_package(package_name):
    try:
        subprocess.run(['dpkg', '-s', package_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{package_name} is already installed.")
    except subprocess.CalledProcessError:
        print(f"{package_name} is not installed. Installing...")
        try:
            subprocess.run(['sudo', 'apt-get', 'install', '-y', package_name], check=True)
            print(f"{package_name} installed successfully.")
        except subprocess.CalledProcessError:
            print(f"Failed to install {package_name}. Please install it manually.")
            sys.exit(1)

# Ensure the required package is installed
install_package('libxcb-xinerama0')

# Unset environment variables to avoid conflicts
os.environ.pop('QT_QPA_PLATFORM_PLUGIN_PATH', None)
os.environ.pop('QT_PLUGIN_PATH', None)

class ServerCheckThread(QThread):
    server_online_signal = pyqtSignal(bool)

    def run(self):
        try:
            response = requests.get("http://192.168.1.101:5000/online_users")
            server_online = response.status_code == 200
        except requests.RequestException:
            server_online = False
        self.server_online_signal.emit(server_online)


class SplashScreen(QWidget):
    update_log = pyqtSignal(str)
    update_progress = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setFixedSize(600, 300)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        # Set background image
        self.background_label = QLabel(self)
        pixmap = QPixmap('/home/mete/Downloads/loading.png')
        self.background_label.setPixmap(pixmap)
        self.background_label.setScaledContents(True)
        self.background_label.setGeometry(0, 0, 600, 300)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        self.label = QLabel("Starting IPFS...")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("color: white; font-size: 18px;")
        layout.addWidget(self.label)

        self.progressBar = QProgressBar(self)
        self.progressBar.setMaximum(100)
        self.progressBar.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 5px;
                text-align: center;
            }

            QProgressBar::chunk {
                background-color: #05B8CC;
                width: 20px;
            }
        """)
        layout.addWidget(self.progressBar)

        self.logOutput = QLabel()
        self.logOutput.setAlignment(Qt.AlignCenter)
        self.logOutput.setStyleSheet("color: white; font-size: 14px;")
        layout.addWidget(self.logOutput)

        self.setLayout(layout)
        self.centerWindow()

    def centerWindow(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def updateLog(self, message):
        print(message)  # Debug print
        self.logOutput.setText(message)

    def updateProgressBar(self, value):
        print(f"Progress: {value}")  # Debug print
        self.progressBar.setValue(value)


class IPFSInitializer(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    ipfs_process = None

    def run(self):
        os_name = platform.system()

        self.log_signal.emit("Checking IPFS installation...")
        time.sleep(1)  # Simulate time-consuming task

        if os_name == 'Linux':
            IPFS_PATH = '/usr/local/bin/ipfs'
            install_commands = [
                "wget https://dist.ipfs.io/go-ipfs/v0.16.0/go-ipfs_v0.16.0_linux-amd64.tar.gz -O /tmp/go-ipfs.tar.gz",
                "tar -xvzf /tmp/go-ipfs.tar.gz -C /tmp",
                "sudo bash /tmp/go-ipfs/install.sh"
            ]
        else:
            self.log_signal.emit(f"Unsupported operating system: {os_name}")
            self.progress_signal.emit(100)
            return

        try:
            result = subprocess.run(['which', 'ipfs'], check=True, capture_output=True, text=True)
            IPFS_PATH = result.stdout.strip()
            self.log_signal.emit(f"IPFS is already installed at {IPFS_PATH}.")
            self.progress_signal.emit(30)
        except subprocess.CalledProcessError:
            self.log_signal.emit("IPFS is not installed. Installing IPFS...")
            try:
                sudo_password = getpass("Enter sudo password: ")
                for cmd in install_commands:
                    if 'sudo' in cmd:
                        cmd = f"echo {sudo_password} | sudo -S {cmd[5:]}"
                    subprocess.run(cmd, shell=True, check=True)
                result = subprocess.run(['which', 'ipfs'], check=True, capture_output=True, text=True)
                IPFS_PATH = result.stdout.strip()
                self.log_signal.emit("IPFS installed successfully.")
                self.progress_signal.emit(60)
            except subprocess.CalledProcessError as e:
                self.log_signal.emit(f"Failed to install IPFS: {e}")
                self.progress_signal.emit(100)
                return

        # Initialize IPFS if not already initialized
        try:
            self.log_signal.emit("Checking if IPFS repository is initialized...")
            result = subprocess.run([IPFS_PATH, 'repo', 'stat'], capture_output=True, text=True)
            if result.returncode != 0:
                self.log_signal.emit("Initializing IPFS repository...")
                result = subprocess.run([IPFS_PATH, 'init'], capture_output=True, text=True)
                if result.returncode == 0:
                    self.log_signal.emit("IPFS repository initialized successfully.")
                else:
                    self.log_signal.emit(f"IPFS repository initialization failed: {result.stderr}")
                    self.progress_signal.emit(100)
                    return
            else:
                self.log_signal.emit("IPFS repository already initialized.")
        except subprocess.CalledProcessError as e:
            self.log_signal.emit(f"Failed to check IPFS repository status: {e}")
            self.progress_signal.emit(100)
            return

        # Run migration tool if needed
        try:
            self.log_signal.emit("Running IPFS migration tool...")
            result = subprocess.run([IPFS_PATH, 'repo', 'migrate'], capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                self.log_signal.emit("IPFS repository migration successful.")
            else:
                self.log_signal.emit(f"Failed to migrate IPFS repository: {result.stderr}")
                self.progress_signal.emit(100)
                return
        except subprocess.TimeoutExpired:
            self.log_signal.emit("IPFS migration tool timed out.")
            self.progress_signal.emit(100)
            return
        except subprocess.CalledProcessError as e:
            self.log_signal.emit(f"Failed to run IPFS migration tool: {e}")
            self.progress_signal.emit(100)
            return

        # Start the IPFS daemon
        try:
            self.log_signal.emit("Starting IPFS daemon...")
            self.ipfs_process = subprocess.Popen([IPFS_PATH, 'daemon'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(3)  # Give some time for the daemon to start
            if self.ipfs_process.poll() is None:
                self.log_signal.emit("IPFS daemon started successfully.")
                self.progress_signal.emit(100)
                self.verify_ipfs(IPFS_PATH)  # Run verification tests
            else:
                stderr = self.ipfs_process.stderr.read().decode()
                if 'daemon is running' in stderr:
                    self.log_signal.emit("IPFS daemon is already running.")
                    self.verify_ipfs(IPFS_PATH)  # Run verification tests
                else:
                    self.log_signal.emit(f"Failed to start IPFS daemon: {stderr}")
                self.progress_signal.emit(100)
        except subprocess.CalledProcessError as e:
            self.log_signal.emit(f"Failed to start IPFS daemon: {e}")
            self.progress_signal.emit(100)
            return

    def verify_ipfs(self, ipfs_path):
        # Check IPFS version
        try:
            result = subprocess.run([ipfs_path, '--version'], capture_output=True, text=True)
            self.log_signal.emit(f"IPFS version: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            self.log_signal.emit(f"Failed to get IPFS version: {e}")

        # Check IPFS ID
        try:
            result = subprocess.run([ipfs_path, 'id'], capture_output=True, text=True)
            self.log_signal.emit(f"IPFS ID: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            self.log_signal.emit(f"Failed to get IPFS ID: {e}")

        # Add and retrieve a test file, then remove it
        try:
            test_file_path = '/tmp/testfile.txt'
            with open(test_file_path, 'w') as f:
                f.write("Hello IPFS")

            result = subprocess.run([ipfs_path, 'add', test_file_path], capture_output=True, text=True)
            if result.returncode == 0 and "added" in result.stdout:
                cid = result.stdout.split()[1]
                self.log_signal.emit(f"Added test file with CID: {cid}")

                result = subprocess.run([ipfs_path, 'cat', cid], capture_output=True, text=True)
                if result.returncode == 0:
                    self.log_signal.emit(f"Retrieved test file content: {result.stdout.strip()}")

                    # Unpin the file to remove it from the local storage
                    subprocess.run([ipfs_path, 'pin', 'rm', cid], capture_output=True, text=True)
                    subprocess.run([ipfs_path, 'repo', 'gc'], capture_output=True, text=True)
                    self.log_signal.emit(f"Removed test file with CID: {cid}")

                    # Clean up the test file
                    os.remove(test_file_path)
                else:
                    self.log_signal.emit(f"Failed to retrieve test file: {result.stderr}")
            else:
                self.log_signal.emit("Failed to add test file: Invalid IPFS add output")

        except subprocess.CalledProcessError as e:
            self.log_signal.emit(f"Failed to add, retrieve, or remove test file: {e}")

    def stop_ipfs_daemon(self):
        if self.ipfs_process and self.ipfs_process.poll() is None:
            self.log_signal.emit("Stopping IPFS daemon...")
            self.ipfs_process.terminate()
            try:
                self.ipfs_process.wait(timeout=10)
                self.log_signal.emit("IPFS daemon stopped successfully.")
            except subprocess.TimeoutExpired:
                self.log_signal.emit("IPFS daemon did not stop in time, killing process...")
                self.ipfs_process.kill()
                self.log_signal.emit("IPFS daemon killed.")



class NodeItem(QListWidgetItem):
    def __init__(self, name, is_online=True):
        super().__init__(name)
        icon_path = '/home/mete/Downloads/green.png' if is_online else '/home/mete/Downloads/red.png'
        self.setIcon(QIcon(icon_path))

class FileDropArea(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.file_path = None
        upload_icon_path = '/home/mete/Downloads/file_icon.png'
        self.setPixmap(QPixmap(upload_icon_path).scaled(64, 64, Qt.KeepAspectRatio))
        self.setStyleSheet("""
            QLabel {
                background-color: rgba(0, 0, 0, 0.5);
                border: 2px dashed #1E90FF;
                font-size: 16px;
            }
        """)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.acceptProposedAction()
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    self.file_path = url.toLocalFile()
                    self.emit_file_dropped(self.file_path)

    def emit_file_dropped(self, filepath):
        print(f"File dropped: {filepath}")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.choose_file()

    def choose_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, 'Open file', '/home', "All files (*)")
        if fname:
            self.file_path = fname
            self.emit_file_dropped(fname)


class PasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Password")
        self.setFixedSize(300, 100)
        layout = QVBoxLayout()

        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_input)

        self.ok_button = QPushButton("OK", self)
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(self.ok_button)

        self.setLayout(layout)

    def get_password(self):
        return self.password_input.text()


class DashboardWindow(QMainWindow):
    def __init__(self, session_token=None, nonce=None, private_key=None):
        super().__init__()
        self.setWindowTitle('Dashboard')
        self.setFixedSize(1500, 900)
        self.centerWindow()
        self.all_nodes = []  # Store all nodes
        self.session_token = session_token
        self.nonce = nonce
        self.private_key = private_key

        if self.session_token and self.nonce:
            self.heartbeat_thread = HeartbeatThread(
                "http://192.168.1.101:5000/heartbeat",
                self.session_token,
                self.nonce,
                self.private_key,
                self.get_username()
            )
            self.heartbeat_thread.start()
        else:
            self.heartbeat_thread = None
            print("Skipping heartbeat as server authentication is not available")

        self.local_db_path = 'local_database.json'

        self.initUI()

        # Start a thread to periodically check the online status of nodes
        self.update_status_thread = NodeStatusUpdateThread(self)
        self.update_status_thread.start()

    def closeEvent(self, event):
        if self.heartbeat_thread:
            self.heartbeat_thread.stop()
            self.heartbeat_thread.wait()
        self.update_status_thread.stop()
        self.update_status_thread.wait()
        event.accept()

    def get_username(self):
        with open('user_config.json', 'r') as config_file:
            user_config = json.load(config_file)
        return user_config['nickname']

    def on_database_checkbox_changed(self, state):
        if state == Qt.Checked:
            self.download_database()
            self.database_thread = DatabaseUpdateThread(self.local_db_path)
            self.database_thread.start()
        else:
            if hasattr(self, 'database_thread'):
                self.database_thread.stop()

    def download_database(self):
        try:
            response = requests.get('http://192.168.1.101:5000/database')
            if response.status_code == 200:
                with open(self.local_db_path, 'w') as f:
                    f.write(response.text)
                print("Database downloaded successfully")
            else:
                print("Failed to download database")
        except requests.RequestException as e:
            print(f"Error downloading database: {e}")


    def initUI(self):
        pixmap = QPixmap('/home/mete/Downloads/fileuploadback.jpg')
        palette = QPalette()
        palette.setBrush(QPalette.Window, QBrush(pixmap))
        self.setPalette(palette)

        self.centralWidget = QWidget(self)
        self.setCentralWidget(self.centralWidget)
        layout = QVBoxLayout(self.centralWidget)

        self.databaseCheckbox = QCheckBox("Activate Database Download", self)
        self.databaseCheckbox.stateChanged.connect(self.on_database_checkbox_changed)
        layout.addWidget(self.databaseCheckbox)

        splitter = QSplitter(Qt.Horizontal)

        self.fileDropArea = FileDropArea(self)
        drop_area_width = int(self.width() * 0.65)
        drop_area_height = int(self.height() * 0.5)
        self.fileDropArea.setFixedSize(drop_area_width, drop_area_height)
        splitter.addWidget(self.fileDropArea)

        self.searchBar = QLineEdit(self)
        self.searchBar.setPlaceholderText("Search nodes...")
        self.searchBar.setStyleSheet("""
                   QLineEdit {
                       background-color: rgba(255, 255, 255, 0.5);
                       border: 1px solid #b3d1ff;
                       padding: 5px;
                       font-size: 16px;
                       color: #003366;
                   }
               """)
        self.searchBar.textChanged.connect(self.filter_nodes)  # Connect search bar

        self.nodeList = QListWidget(self)
        self.nodeList.setSelectionMode(QListWidget.MultiSelection)  # Allow multiple selections
        nodeListWidth = self.width() - drop_area_width - 20
        nodeListHeight = drop_area_height - self.searchBar.height() - 10
        self.nodeList.setFixedSize(nodeListWidth, nodeListHeight)
        self.nodeList.setStyleSheet("""
                    QListWidget {
                        background-color: #e6f2ff;
                        border: 2px solid #1E90FF;
                        color: #003366;
                    }
                    QListWidget::item:selected {
                        background-color: #b3d1ff;
                    }
                """)

        nodeLayout = QVBoxLayout()
        nodeLayout.addWidget(self.searchBar)
        nodeLayout.addWidget(self.nodeList)
        nodeWidget = QWidget()
        nodeWidget.setLayout(nodeLayout)
        splitter.addWidget(nodeWidget)

        self.populateNodes()

        self.smallFileDropArea = FileDropArea(self)
        small_drop_area_size = QSize(200, 100)
        self.smallFileDropArea.setFixedSize(small_drop_area_size)
        self.smallFileDropArea.move(
            self.width() - small_drop_area_size.width() - 20,
            self.height() - small_drop_area_size.height() - 100
        )

        self.getFileButton = QPushButton('Get File', self)
        self.getFileButton.setFixedSize(200, 40)
        self.getFileButton.move(
            self.smallFileDropArea.x(),
            self.smallFileDropArea.y() + self.smallFileDropArea.height() + 10
        )
        self.getFileButton.setStyleSheet("""
                   QPushButton {
                       background-color: #28a745;
                       color: white;
                       font-size: 18px;
                       border-radius: 10px;
                   }
                   QPushButton:hover {
                       background-color: #34d058;
                   }
               """)

        self.getFileButton.clicked.connect(self.on_get_file_button_clicked)

        self.sendButton = QPushButton('Send', self)
        self.sendButton.setFixedSize(drop_area_width, 100)
        self.sendButton.setStyleSheet("""
            QPushButton {
                background-color: #3399ff;
                color: white;
                font-size: 22px;
                border-radius: 10px;
                margin-top: 20px;
            }
            QPushButton:hover {
                background-color: #66b3ff;
            }
        """)
        self.sendButton.clicked.connect(self.on_send_button_clicked)

        self.registerButton = QPushButton('Register', self)
        self.registerButton.setStyleSheet("""
                    QPushButton {
                        background-color: #FFA500;
                        color: white;
                        font-size: 18px;
                        border-radius: 10px;
                    }
                    QPushButton:hover {
                        background-color: #FFB347;
                    }
                """)
        self.registerButton.setFixedSize(200, 40)
        self.registerButton.move(self.width() - self.registerButton.width() - 20, 20)
        self.registerButton.clicked.connect(self.on_register_button_clicked)

        layout.addWidget(splitter, Qt.AlignCenter)
        layout.addWidget(self.sendButton, Qt.AlignCenter)
        splitter.setSizes([drop_area_width, nodeListWidth])

    def centerWindow(self):
        centerPoint = QDesktopWidget().availableGeometry().center()
        self.move(centerPoint.x() - self.width() // 2, centerPoint.y() - self.height() // 2)

    def on_send_button_clicked(self):
        selected_items = self.nodeList.selectedItems()
        if not selected_items:
            print("No nodes selected")
            return

        file_path = self.fileDropArea.file_path
        if not file_path:
            print("No file selected")
            return

        encrypted_file_path = file_path + ".enc"
        encrypted_aes_keys = []
        email_list = []  # List to store node names and emails
        json_paths = []  # List to store JSON file paths

        for item in selected_items:
            node_name = item.text()
            user_details = self.get_user_details(node_name)
            if user_details:
                public_key_str = user_details[-1]
                email = user_details[3]
                print(f"Public Key for {node_name}: {public_key_str}")  # Debugging statement
                encrypted_aes_key = self.encrypt_file(public_key_str, file_path, encrypted_file_path)
                encrypted_aes_keys.append((node_name, encrypted_aes_key))
                email_list.append((node_name, email))  # Append node name and email
            else:
                print(f"Node details not found for {node_name}")

        if not encrypted_aes_keys:
            print("No valid user details found")
            return

        cid = self.upload_to_ipfs(encrypted_file_path)
        username = self.get_username()

        for node_name, encrypted_aes_key in encrypted_aes_keys:
            json_file_path = self.create_json_file(cid, username, encrypted_aes_key, node_name,
                                                   os.path.basename(file_path))
            print(f"JSON file created for {node_name} at: {json_file_path}")
            json_paths.append(json_file_path)  # Append JSON file path

        self.show_summary_window(email_list, json_paths)  # Show the summary window

    def show_summary_window(self, email_list, json_paths):
        summary_text = "Emails and JSON File Paths:\n\n"

        for node_name, email in email_list:
            summary_text += f"{node_name} - {email}\n"

        summary_text += "\nJSON File Paths:\n"
        for path in json_paths:
            summary_text += f"{path}\n"

        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("Summary")
        msg.setText(summary_text)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def get_user_details(self, nickname):
        try:
            # Attempt to get user details from the server
            conn = pyodbc.connect(
                'DRIVER={ODBC Driver 17 for SQL Server};SERVER=192.168.1.101,1435;DATABASE=FileSharingDB;UID=sa;PWD=MeTe14531915.;TrustServerCertificate=yes')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM [User] WHERE nickname = ?", nickname)
            row = cursor.fetchone()
            conn.close()
            if row:
                return row
        except pyodbc.OperationalError as e:
            print(f"Server connection failed: {e}")

        # Fallback to local database
        return self.get_user_details_from_local(nickname)

    def get_user_details_from_local(self, nickname):
        try:
            with open(self.local_db_path, 'r') as f:
                data = json.load(f)
            for entry in data:
                if entry['nickname'] == nickname:
                    return entry['nickname'], entry['email'], entry['public_key']
        except Exception as e:
            print(f"Error reading local database: {e}")
        return None

    def encrypt_file(self, public_key_str, input_file_path, output_file_path):
        try:
            # Generate a random AES key
            aes_key = secrets.token_bytes(32)  # 256-bit key

            # Encrypt the file with AES
            with open(input_file_path, 'rb') as f:
                plaintext = f.read()

            # Padding for AES encryption
            padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            iv = secrets.token_bytes(16)  # 128-bit IV for AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Write the encrypted file
            with open(output_file_path, 'wb') as f:
                f.write(iv + ciphertext)

            # Convert the public key string to a public key object
            public_key = serialization.load_pem_public_key(public_key_str.encode('utf-8'))

            # Encrypt the AES key with the recipient's public RSA key
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            print(f"File encrypted successfully and saved to {output_file_path}")
            return encrypted_aes_key
        except Exception as e:
            print(f"Encryption failed: {str(e)}")
            raise

    def upload_to_ipfs(self, file_path):
        result = subprocess.run(['ipfs', 'add', file_path], capture_output=True, text=True)
        cid = result.stdout.split()[1]
        return cid

    def create_json_file(self, cid, sender_nickname, encrypted_aes_key, receiver_name, original_file_name):
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
        data = {
            "Root CID": cid,
            "Sender": sender_nickname,
            "Encrypted AES Key": encrypted_aes_key_b64
        }
        # Create a string to sign that includes the encrypted AES key
        string_to_sign = cid + sender_nickname + encrypted_aes_key_b64
        data["Signature"] = self.create_signature(string_to_sign)

        json_file_name = f"{receiver_name}_{original_file_name}.json"
        json_file_path = os.path.join("/tmp", json_file_name)
        with open(json_file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        return json_file_path

    def create_signature(self, data):
        if not self.private_key:
            raise ValueError("Private key is not available")

        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature.hex()

    def on_get_file_button_clicked(self):
        json_file_path = self.smallFileDropArea.file_path
        if json_file_path and json_file_path.endswith('.json'):
            with open(json_file_path, 'r') as json_file:
                data = json.load(json_file)

            # Validate the signature
            sender_nickname = data["Sender"]
            signature = bytes.fromhex(data["Signature"])
            string_to_sign = data["Root CID"] + data["Sender"] + data["Encrypted AES Key"]

            if self.validate_signature(sender_nickname, string_to_sign, signature):
                receiver_name = json_file_path.split('/')[-1].split('_')[0]
                encrypted_file_path = '/tmp/encrypted_file.enc'
                output_file_path = os.path.join(os.path.dirname(json_file_path), f'{receiver_name}_decrypted_file')

                # Download the encrypted file from IPFS
                cid = data["Root CID"]
                self.download_from_ipfs(cid, encrypted_file_path)

                # Decrypt the file
                encrypted_aes_key_b64 = data["Encrypted AES Key"]
                self.decrypt_file(encrypted_file_path, output_file_path, encrypted_aes_key_b64)

                # Delete the encrypted file
                os.remove(encrypted_file_path)

                print(f"Decryption complete. Decrypted file saved to {output_file_path}")
            else:
                print("Invalid signature. Aborting file download.")
        else:
            print("No valid JSON file selected.")

    def validate_signature(self, sender_nickname, data, signature):
        user_details = self.get_user_details(sender_nickname)
        if user_details:
            public_key_str = user_details[-1]
            public_key = serialization.load_pem_public_key(public_key_str.encode('utf-8'))

            try:
                public_key.verify(
                    signature,
                    data.encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                return True
            except Exception as e:
                print(f"Signature validation failed: {str(e)}")
                return False
        return False

    def download_from_ipfs(self, cid, output_file_path):
        result = subprocess.run(['ipfs', 'get', cid, '-o', output_file_path], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Failed to download file from IPFS: {result.stderr}")
        print(f"File downloaded from IPFS: {output_file_path}")

    def decrypt_file(self, encrypted_file_path, output_file_path, encrypted_aes_key_b64):
        try:
            if not self.private_key:
                raise ValueError("Private key is not available")

            # Decode the base64 encoded AES key
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

            # Decrypt the AES key using the recipient's private RSA key
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Read the encrypted file content
            with open(encrypted_file_path, 'rb') as f:
                iv = f.read(16)  # The first 16 bytes are the IV
                ciphertext = f.read()

            # Decrypt the file content using the AES key
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove padding
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            # Write the decrypted content to the output file
            with open(output_file_path, 'wb') as f:
                f.write(plaintext)

            print(f"File decrypted successfully and saved to {output_file_path}")

        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            raise

    def on_register_button_clicked(self):
        self.register_window = RegisterWindow()
        self.register_window.show()
        self.hide()

    def is_server_online(self):
        try:
            response = requests.get("http://192.168.1.101:5000/online_users")
            return response.status_code == 200
        except requests.RequestException:
            return False

    def load_local_database(self):
        if os.path.exists(self.local_db_path):
            with open(self.local_db_path, 'r') as f:
                data = json.load(f)
            for entry in data:
                nickname = entry['nickname']
                is_online = False #Everybody seems offline if the server is down.
                self.addNode(nickname, is_online)
                self.all_nodes.append((nickname, is_online))  # Store all nodes
        else:
            print("No local database found")

    def populateNodes(self):
        try:
            if self.is_server_online():
                conn = pyodbc.connect(
                    'DRIVER={ODBC Driver 17 for SQL Server};SERVER=192.168.1.101,1435;DATABASE=FileSharingDB;UID=sa;PWD=MeTe14531915.;TrustServerCertificate=yes')
                cursor = conn.cursor()
                cursor.execute("SELECT nickname FROM [User]")
                rows = cursor.fetchall()
                conn.close()

                for row in rows:
                    nickname = row[0]
                    is_online = False
                    self.addNode(nickname, is_online)
                    self.all_nodes.append((nickname, is_online))  # Store all nodes
            else:
                if os.path.exists(self.local_db_path):
                    self.load_local_database()
                    QMessageBox.warning(self, "Warning", "Using local database as server is not available.")
                else:
                    QMessageBox.warning(self, "Warning", "No local database found and server is not available.")
        except Exception as e:
            print(f"Error populating nodes: {e}")
            if os.path.exists(self.local_db_path):
                self.load_local_database()
                QMessageBox.warning(self, "Warning", "Using local database due to an error.")
            else:
                QMessageBox.warning(self, "Warning", "No local database found and an error occurred.")

    def addNode(self, name, is_online):
        node_item = NodeItem(name, is_online)
        self.nodeList.addItem(node_item)

    def update_node_status(self):
        try:
            response = requests.get('http://192.168.1.101:5000/online_users')
            if response.status_code == 200:
                online_users = response.json()
                for i in range(self.nodeList.count()):
                    item = self.nodeList.item(i)
                    item.setIcon(QIcon(
                        '/home/mete/Downloads/green.png' if item.text() in online_users else '/home/mete/Downloads/red.png'))
            else:
                print("Failed to get online users")
        except requests.RequestException as e:
            print(f"Error getting online users: {e}")


    def filter_nodes(self, text):
        self.nodeList.clear()  # Clear the current list
        for name, is_online in self.all_nodes:
            if text.lower() in name.lower():
                self.addNode(name, is_online)

class NodeStatusUpdateThread(QThread):
    def __init__(self, dashboard_window, interval=10):
        super().__init__()
        self.dashboard_window = dashboard_window
        self.interval = interval
        self.running = True

    def run(self):
        while self.running:
            self.dashboard_window.update_node_status()
            time.sleep(self.interval)

    def stop(self):
        self.running = False

class DatabaseUpdateThread(QThread):
    def __init__(self, local_db_path, interval=60):
        super().__init__()
        self.local_db_path = local_db_path
        self.interval = interval
        self.running = True

    def run(self):
        while self.running:
            self.update_database()
            time.sleep(self.interval)

    def update_database(self):
        try:
            response = requests.get('http://192.168.1.101:5000/database')
            if response.status_code == 200:
                with open(self.local_db_path, 'w') as f:
                    f.write(response.text)
                print("Local database updated successfully")
            else:
                print("Failed to update local database")
        except requests.RequestException as e:
            print(f"Error updating local database: {e}")

    def stop(self):
        self.running = False


class RegisterWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Register')
        self.resize(1000, 600)
        self.centerWindow()
        self.initUI()

    def initUI(self):
        pixmap = QPixmap('/home/mete/Documents/arkaplan2.png')
        palette = QPalette()
        palette.setBrush(QPalette.Window, QBrush(pixmap))
        self.setPalette(palette)

        mainLayout = QVBoxLayout(self)
        mainLayout.setContentsMargins(0, 0, 0, 0)

        self.nicknameInput = QLineEdit()
        self.nicknameInput.setPlaceholderText("Nickname")
        self.nicknameInput.setFixedSize(300, 40)
        self.applyStyle(self.nicknameInput)

        self.emailInput = QLineEdit()
        self.emailInput.setPlaceholderText("Email")
        self.emailInput.setFixedSize(300, 40)
        self.applyStyle(self.emailInput)

        self.passwordInput = QLineEdit()
        self.passwordInput.setPlaceholderText("Password")
        self.passwordInput.setEchoMode(QLineEdit.Password)
        self.passwordInput.setFixedSize(300, 40)
        self.applyStyle(self.passwordInput)

        self.registerButton = QPushButton('Register')
        self.registerButton.setFixedSize(300, 40)
        self.registerButton.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border-radius: 20px;
                font-size: 18px;
            }
            QPushButton:hover {
                background-color: #34d058;
            }
        """)
        self.registerButton.clicked.connect(self.on_register_button_clicked)

        mainLayout.addStretch(1)
        mainLayout.addWidget(self.nicknameInput, alignment=Qt.AlignCenter)
        mainLayout.addWidget(self.passwordInput, alignment=Qt.AlignCenter)
        mainLayout.addWidget(self.emailInput, alignment=Qt.AlignCenter)
        mainLayout.addWidget(self.registerButton, alignment=Qt.AlignCenter)
        mainLayout.addStretch(1)

        self.setLayout(mainLayout)

    def applyStyle(self, widget):
        widget.setStyleSheet("""
            QLineEdit {
                border: 2px solid #3399ff;
                border-radius: 15px;
                padding: 5px;
                font-size: 18px;
            }
        """)

    def centerWindow(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def on_register_button_clicked(self):
        nickname = self.nicknameInput.text()
        email = self.emailInput.text()
        password = self.passwordInput.text()

        private_key, public_key = self.generate_asymmetric_key_pair(nickname, email, password)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        data = {
            'nickname': nickname,
            'email': email,
            'password': password,
            'public_key': public_key_pem
        }

        response = requests.post('http://192.168.1.101:5000/register', json=data)
        if response.status_code == 200:
            # Store the username locally
            with open('user_config.json', 'w') as config_file:
                json.dump({'nickname': nickname}, config_file)

            print(f"Registered with nickname: {nickname}, email: {email}")
            self.dashboard = DashboardWindow()
            self.dashboard.show()
            self.hide()
        else:
            print("Registration failed")

    def generate_asymmetric_key_pair(self, nickname, email, password):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        with open(f"{nickname}_private_key.pem", 'wb') as f:
            f.write(private_key_pem)

        with open(f"{nickname}_public_key.pem", 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print(f"Asymmetric key pair generated for {nickname}")
        return private_key, public_key

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Login')
        self.resize(1000, 600)
        self.centerWindow()
        self.session_token = None
        self.nonce = None
        self.private_key = None
        self.nickname = None  # Add this line to initialize nickname
        self.initUI()

    def initUI(self):
        pixmap = QPixmap('/home/mete/Documents/arkaplan2.png')
        palette = QPalette()
        palette.setBrush(QPalette.Window, QBrush(pixmap))
        self.setPalette(palette)

        mainLayout = QHBoxLayout(self)
        mainLayout.setContentsMargins(0, 0, 0, 0)

        inputContainer = QVBoxLayout()
        inputContainer.setSpacing(3)
        inputContainer.setContentsMargins(90, 150, 60, 50)

        self.passwordInput = QLineEdit()
        self.passwordInput.setPlaceholderText("password")
        self.passwordInput.setFixedSize(300, 40)
        self.passwordInput.setEchoMode(QLineEdit.Password)
        self.passwordInput.setStyleSheet("""
            QLineEdit {
                background-color: white;
                color: black;
                border: 1px solid gray;
                border-radius: 0px;
                padding: 10px;
                font-size: 16px;
            }
        """)

        self.loginButton = QPushButton('Log In')
        self.loginButton.setFixedSize(300, 40)
        self.loginButton.setStyleSheet("""
            QPushButton {
                background-color: #3399ff;
                color: white;
                border: none;
                border-radius: 0px;
                padding: 10px 20px;
                font-size: 18px;
            }
            QPushButton:hover {
                background-color: #66b3ff;
            }
        """)
        self.loginButton.clicked.connect(self.on_login_button_clicked)

        spacerItem = QWidget()
        spacerItem.setFixedSize(300, 20)

        self.registerButton = QPushButton('Register')
        self.registerButton.setFixedSize(300, 40)
        self.registerButton.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: 1px solid #28a745;
                border-radius: 0px;
                padding: 10px 20px;
                font-size: 18px;
            }
            QPushButton:hover {
                background-color: #34d058;
            }
        """)
        self.registerButton.clicked.connect(self.on_register_button_clicked)

        inputContainer.addWidget(self.passwordInput)
        inputContainer.addWidget(self.loginButton)
        inputContainer.addWidget(spacerItem)
        inputContainer.addWidget(self.registerButton)
        inputContainer.addStretch(1)

        paddedLayout = QHBoxLayout()
        paddedLayout.addLayout(inputContainer)
        paddedLayout.addStretch()

        mainLayout.addLayout(paddedLayout)
        mainLayout.addStretch(1)

        self.setLayout(mainLayout)

    def on_login_button_clicked(self):
        password = self.passwordInput.text()

        # Read the stored username
        with open('user_config.json', 'r') as config_file:
            user_config = json.load(config_file)

        self.nickname = user_config['nickname']  # Update self.nickname here
        private_key_path = f'{self.nickname}_private_key.pem'

        try:
            # Load the recipient's private key
            with open(private_key_path, 'rb') as key_file:
                self.private_key = serialization.load_pem_private_key(key_file.read(), password=password.encode())

            # Check if server is online in a separate thread
            self.server_check_thread = ServerCheckThread()
            self.server_check_thread.server_online_signal.connect(self.on_server_check_finished)
            self.server_check_thread.start()
        except Exception as e:
            print(f"Login failed: {str(e)}")

    def on_server_check_finished(self, server_online):
        if server_online:
            print("Attempting server authentication...")
            # Create the initial authentication data
            timestamp = str(int(time.time()))
            nonce = secrets.token_hex(16)
            data_to_sign = self.nickname + timestamp + nonce  # Use self.nickname
            signature = self.private_key.sign(
                data_to_sign.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            auth_data = {
                'username': self.nickname,  # Use self.nickname
                'timestamp': timestamp,
                'nonce': nonce,
                'signature': signature.hex()
            }
            response = requests.post('http://192.168.1.101:5000/authenticate', json=auth_data)
            if response.status_code == 200:
                self.session_token = response.json()['session_token']
                self.nonce = response.json()['nonce']
                print("Login successful (server authenticated)")
                self.dashboard = DashboardWindow(session_token=self.session_token, nonce=self.nonce,
                                                 private_key=self.private_key)
                self.dashboard.show()
                self.hide()
            else:
                print("Authentication failed")
        else:
            print("Server is offline, falling back to local authentication")
            self.dashboard = DashboardWindow(private_key=self.private_key)
            self.dashboard.show()
            self.hide()

    def centerWindow(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def on_register_button_clicked(self):
        self.register_window = RegisterWindow()
        self.register_window.show()
        self.hide()

class HeartbeatThread(QThread):
    def __init__(self, server_url, session_token, nonce, private_key, username, interval=10):
        super().__init__()
        self.server_url = server_url
        self.session_token = session_token
        self.nonce = nonce
        self.private_key = private_key
        self.username = username
        self.interval = interval
        self.running = True

    def run(self):
        while self.running:
            self.send_heartbeat()
            time.sleep(self.interval)

    def send_heartbeat(self):
        try:
            signed_nonce = self.private_key.sign(
                self.nonce.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            ).hex()
            heartbeat_data = {
                'username': self.username,
                'session_token': self.session_token,
                'signed_nonce': signed_nonce
            }
            response = requests.post(self.server_url, json=heartbeat_data)
            if response.status_code == 200:
                new_nonce = response.json().get('nonce')
                self.nonce = new_nonce
                print("Heartbeat successful")
            else:
                print(f"Heartbeat failed with status code: {response.status_code}")
        except requests.RequestException as e:
            print(f"Heartbeat error: {e}")

    def stop(self):
        self.running = False


def main():
    app = QApplication(sys.argv)

    splash = SplashScreen()
    splash.show()

    ipfs_initializer = IPFSInitializer()
    ipfs_initializer.log_signal.connect(splash.updateLog)
    ipfs_initializer.progress_signal.connect(splash.updateProgressBar)
    ipfs_initializer.start()

    def on_ipfs_init_finished():
        print("IPFS initialization finished")  # Debug print
        splash.close()
        start_main_app()

    ipfs_initializer.finished.connect(on_ipfs_init_finished)

    def cleanup():
        ipfs_initializer.stop_ipfs_daemon()

    app.aboutToQuit.connect(cleanup)

    sys.exit(app.exec_())


def start_main_app():
    login = LoginWindow()
    login.show()
    global main_window
    main_window = login


if __name__ == '__main__':
    main()


import sys
import os
import subprocess
from getpass import getpass
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QPushButton, QApplication, QLabel,
                             QDesktopWidget, QHBoxLayout, QListWidgetItem, QSplitter, QListWidget, QFileDialog,
                             QLineEdit, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QPixmap, QPalette, QBrush, QIcon
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import platform
import time

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
        pixmap = QPixmap('/home/mete/Downloads/loading.png')  # Replace with your image file path
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

    def run(self):
        os_name = platform.system()

        self.log_signal.emit("Checking IPFS installation...")
        time.sleep(1)  # Simulate time-consuming task

        if os_name == 'Linux':
            IPFS_PATH = '/usr/local/bin/ipfs'
            install_commands = [
                "wget https://dist.ipfs.io/go-ipfs/v0.8.0/go-ipfs_v0.8.0_linux-amd64.tar.gz -O /tmp/go-ipfs.tar.gz",
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

        # Check if IPFS daemon is running
        try:
            result = subprocess.run([IPFS_PATH, 'id'], capture_output=True, text=True)
            if result.returncode == 0:
                self.log_signal.emit("IPFS daemon is already running.")
                self.progress_signal.emit(60)
                self.verify_ipfs(IPFS_PATH)  # Run verification tests
                return
        except subprocess.CalledProcessError:
            self.log_signal.emit("IPFS daemon is not running. Initializing IPFS...")

        # Improved initialization check with detailed error logging
        try:
            result = subprocess.run([IPFS_PATH, 'init'], capture_output=True, text=True)
            if result.returncode == 0:
                self.log_signal.emit("IPFS initialized successfully.")
                self.progress_signal.emit(80)
            elif 'ipfs configuration file already exists' in result.stderr:
                self.log_signal.emit("IPFS is already initialized.")
                self.progress_signal.emit(80)
            else:
                self.log_signal.emit(f"Failed to initialize IPFS node: {result.stderr}")
                self.progress_signal.emit(100)
                return
        except subprocess.CalledProcessError as e:
            self.log_signal.emit(f"Failed to initialize IPFS node: {e}")
            self.progress_signal.emit(100)
            return

        # Start the IPFS daemon
        try:
            result = subprocess.Popen([IPFS_PATH, 'daemon'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(5)  # Give some time for the daemon to start
            if result.poll() is None:
                self.log_signal.emit("IPFS daemon started successfully.")
                self.progress_signal.emit(100)
                self.verify_ipfs(IPFS_PATH)  # Run verification tests
            else:
                stderr = result.stderr.read().decode()
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
            cid = result.stdout.split()[1]
            self.log_signal.emit(f"Added test file with CID: {cid}")

            result = subprocess.run([ipfs_path, 'cat', cid], capture_output=True, text=True)
            self.log_signal.emit(f"Retrieved test file content: {result.stdout.strip()}")

            # Unpin the file to remove it from the local storage
            subprocess.run([ipfs_path, 'pin', 'rm', cid], capture_output=True, text=True)
            subprocess.run([ipfs_path, 'repo', 'gc'], capture_output=True, text=True)
            self.log_signal.emit(f"Removed test file with CID: {cid}")

            # Clean up the test file
            os.remove(test_file_path)

        except subprocess.CalledProcessError as e:
            self.log_signal.emit(f"Failed to add, retrieve, or remove test file: {e}")




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
                    self.emit_file_dropped(url.toLocalFile())

    def emit_file_dropped(self, filepath):
        print(f"File dropped: {filepath}")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.choose_file()

    def choose_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, 'Open file', '/home', "All files (*)")
        if fname:
            self.emit_file_dropped(fname)


class DashboardWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Dashboard')
        self.setFixedSize(1500, 900)
        self.centerWindow()
        self.initUI()

    def initUI(self):
        pixmap = QPixmap('/home/mete/Downloads/fileuploadback.jpg')
        palette = QPalette()
        palette.setBrush(QPalette.Window, QBrush(pixmap))
        self.setPalette(palette)

        self.centralWidget = QWidget(self)
        self.setCentralWidget(self.centralWidget)
        layout = QVBoxLayout(self.centralWidget)

        splitter = QSplitter(Qt.Horizontal)

        self.fileDropArea = FileDropArea(self)
        drop_area_width = int(self.width() * 0.65)
        drop_area_height = int(self.height() * 0.5)
        self.fileDropArea.setFixedSize(drop_area_width, drop_area_height)
        splitter.addWidget(self.fileDropArea)

        self.searchBar = QLineEdit(self)
        self.searchBar.setPlaceholderText("Search nodes...")
        self.searchBar
        self.searchBar.setStyleSheet("""
                   QLineEdit {
                       background-color: rgba(255, 255, 255, 0.5);
                       border: 1px solid #b3d1ff;
                       padding: 5px;
                       font-size: 16px;
                       color: #003366;
                   }
               """)

        self.nodeList = QListWidget(self)
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

    def encrypt_file(self, public_key_path, input_file_path, output_file_path):
        with open(public_key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        with open(input_file_path, 'rb') as f:
            plaintext = f.read()

        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_file_path, 'wb') as f:
            f.write(ciphertext)

    def decrypt_file(self, private_key_path, input_file_path, output_file_path, password):
        with open(private_key_path, 'rb') as key_file:
            encrypted_private_key = key_file.read()

        private_key = serialization.load_pem_private_key(
            encrypted_private_key,
            password=password.encode()
        )

        with open(input_file_path, 'rb') as f:
            ciphertext = f.read()

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_file_path, 'wb') as f:
            f.write(plaintext)

    def addNode(self, name, is_online):
        node_item = NodeItem(name, is_online)
        self.nodeList.addItem(node_item)

    def centerWindow(self):
        centerPoint = QDesktopWidget().availableGeometry().center()
        self.move(centerPoint.x() - self.width() // 2, centerPoint.y() - self.height() // 2)

    def on_send_button_clicked(self):
        print("Send button clicked")

    def populateNodes(self):
        self.addNode("Node 1", True)
        self.addNode("Node 2", False)
        self.addNode("Node 3", True)
        self.addNode("Node 4", True)
        self.addNode("Node 5", False)

    def on_get_file_button_clicked(self):
        print("Get File button clicked")

    def on_register_button_clicked(self):
        self.register_window = RegisterWindow()
        self.register_window.show()
        self.hide()


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
        self.generate_asymmetric_key_pair(nickname, email, password)
        print(f"Registered with nickname: {nickname}, email: {email}")
        self.dashboard = DashboardWindow()
        self.dashboard.show()
        self.hide()

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

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(f"{nickname}_public_key.pem", 'wb') as f:
            f.write(public_key_pem)

        print(f"Asymmetric key pair generated for {nickname}")


class LoginWindow(QWidget):
    def __init__(self):

        super().__init__()
        self.setWindowTitle('Login')
        self.resize(1000, 600)
        self.centerWindow()
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

        self.emailInput = QLineEdit()
        self.emailInput.setPlaceholderText("e-mail")
        self.emailInput.setFixedSize(300, 40)
        self.emailInput.setStyleSheet("""
            QLineEdit {
                background-color: white;
                color: black;
                border: 1px solid gray;
                border-radius: 0px;
                padding: 10px;
                font-size: 16px;
            }
        """)

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

        inputContainer.addWidget(self.emailInput)
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
        print("Login button clicked")
        self.hide()
        self.dashboard = DashboardWindow()
        self.dashboard.show()

    def centerWindow(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def on_register_button_clicked(self):
        self.register_window = RegisterWindow()
        self.register_window.show()
        self.hide()


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

    sys.exit(app.exec_())


def start_main_app():
    login = LoginWindow()
    login.show()
    global main_window
    main_window = login


if __name__ == '__main__':
    main()


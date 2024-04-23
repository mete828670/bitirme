import sys
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QPushButton, QApplication, QLabel,
                             QDesktopWidget, QHBoxLayout, QListWidgetItem, QSplitter, QListWidget, QFileDialog,
                             QLineEdit)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QPixmap, QPalette, QBrush, QIcon

class NodeItem(QListWidgetItem):
    def __init__(self, name, is_online=True):
        super().__init__(name)
        # Set the icon based on the online status
        icon_path = '/home/mete/Downloads/green.png' if is_online else '/home/mete/Downloads/red.png'
        self.setIcon(QIcon(icon_path))

class FileDropArea(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        upload_icon_path = '/home/mete/Downloads/file_icon.png'  # Replace with your icon file path
        self.setPixmap(QPixmap(upload_icon_path).scaled(64, 64, Qt.KeepAspectRatio))
        self.setStyleSheet("""
            QLabel {
                background-color: rgba(0, 0, 0, 0.5);  /* Darker background with transparency */
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
        print(f"File dropped: {filepath}")  # Here you can handle the file

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
        self.setFixedSize(1500, 900)  # Fixed size for consistency
        self.centerWindow()
        self.initUI()

    def initUI(self):
        pixmap = QPixmap('/home/mete/Downloads/fileuploadback.jpg')  # Replace with your image file path
        palette = QPalette()
        palette.setBrush(QPalette.Window, QBrush(pixmap))
        self.setPalette(palette)


        self.centralWidget = QWidget(self)
        self.setCentralWidget(self.centralWidget)
        layout = QVBoxLayout(self.centralWidget)

        # Splitter for file area and node list
        splitter = QSplitter(Qt.Horizontal)

        # File drop area setup
        self.fileDropArea = FileDropArea(self)
        drop_area_width = int(self.width() * 0.65)  # Reduced width
        drop_area_height = int(self.height() * 0.5)
        self.fileDropArea.setFixedSize(drop_area_width, drop_area_height)
        splitter.addWidget(self.fileDropArea)

        # Search bar setup
        self.searchBar = QLineEdit(self)
        self.searchBar.setPlaceholderText("Search nodes...")
        self.searchBar.setStyleSheet("""
                   QLineEdit {
                       background-color: rgba(255, 255, 255, 0.5);  /* Semi-transparent background */
                       border: 1px solid #b3d1ff;  /* Light blue border */
                       padding: 5px;
                       font-size: 16px;
                       color: #003366;  /* Darker blue text */
                   }
               """)

        # Node list setup
        # Node list setup with additional height reduction for the search bar
        self.nodeList = QListWidget(self)
        nodeListWidth = self.width() - drop_area_width - 20  # Adjust as needed
        nodeListHeight = drop_area_height - self.searchBar.height() - 10  # Subtract search bar height and some margin
        self.nodeList.setFixedSize(nodeListWidth, nodeListHeight)
        self.nodeList.setStyleSheet("""
                    QListWidget {
                        background-color: #e6f2ff;  /* Light blue background */
                        border: 2px solid #1E90FF;  /* Blue border */
                        color: #003366;  /* Darker blue text */
                    }
                    QListWidget::item:selected {
                        background-color: #b3d1ff;  /* Even lighter blue for selected item */
                    }
                """)

        # Add search bar and node list to a QVBoxLayout
        nodeLayout = QVBoxLayout()
        nodeLayout.addWidget(self.searchBar)
        nodeLayout.addWidget(self.nodeList)
        nodeWidget = QWidget()
        nodeWidget.setLayout(nodeLayout)
        splitter.addWidget(nodeWidget)

        self.populateNodes()

        # Send button setup
        self.sendButton = QPushButton('Send', self)
        self.sendButton.setFixedSize(drop_area_width, 100)  # Match width of file drop area
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

        # Add splitter to the layout
        layout.addWidget(splitter, Qt.AlignCenter)
        layout.addWidget(self.sendButton, Qt.AlignCenter)

        # Ensure splitter expands fully
        splitter.setSizes([drop_area_width, nodeListWidth])

    def addNode(self, name, is_online):
        node_item = NodeItem(name, is_online)
        self.nodeList.addItem(node_item)

    def centerWindow(self):
        centerPoint = QDesktopWidget().availableGeometry().center()
        self.move(centerPoint.x() - self.width() // 2, centerPoint.y() - self.height() // 2)

    def on_send_button_clicked(self):
        print("Send button clicked")
        # Implement the file sending logic here

    def populateNodes(self):
        # Example nodes with alternating online status
        self.addNode("Node 1", True)
        self.addNode("Node 2", False)
        self.addNode("Node 3", True)
        self.addNode("Node 4", True)
        self.addNode("Node 5", False)


class RegisterWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Register')
        self.resize(1000, 600)
        self.centerWindow()
        self.initUI()

    def initUI(self):
        # Set the background image using the same palette as the Login window
        pixmap = QPixmap('/home/mete/Documents/arkaplan2.png')  # Replace with your image file path
        palette = QPalette()
        palette.setBrush(QPalette.Window, QBrush(pixmap))
        self.setPalette(palette)

        # Create a main layout
        mainLayout = QVBoxLayout(self)
        mainLayout.setContentsMargins(0, 0, 0, 0)  # Zero margins for the layout

        # Nickname input
        self.nicknameInput = QLineEdit()
        self.nicknameInput.setPlaceholderText("Nickname")
        self.nicknameInput.setFixedSize(300, 40)
        self.applyStyle(self.nicknameInput)

        # Email input
        self.emailInput = QLineEdit()
        self.emailInput.setPlaceholderText("Email")
        self.emailInput.setFixedSize(300, 40)
        self.applyStyle(self.emailInput)

        # Password input
        self.passwordInput = QLineEdit()
        self.passwordInput.setPlaceholderText("Password")
        self.passwordInput.setEchoMode(QLineEdit.Password)
        self.passwordInput.setFixedSize(300, 40)
        self.applyStyle(self.passwordInput)

        # Register button
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

        # Adding widgets to the layout
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
        # Center the window on the screen
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Login')
        self.resize(1000, 600)
        self.centerWindow()
        self.initUI()

    def initUI(self):
        # Set the background image using palette to fill the entire window
        pixmap = QPixmap('/home/mete/Documents/arkaplan2.png')  # Replace with your image file path
        palette = QPalette()
        palette.setBrush(QPalette.Window, QBrush(pixmap))
        self.setPalette(palette)

        # Create a main layout with zero margin
        mainLayout = QHBoxLayout(self)
        mainLayout.setContentsMargins(0, 0, 0, 0)

        # Container for input fields and button, placed inside a QVBoxLayout
        inputContainer = QVBoxLayout()
        inputContainer.setSpacing(3)  # Reduce space between widgets

        # Add padding inside the input container
        inputContainer.setContentsMargins(90,150,60, 50) # Left, Top, Right, Bottom

        # Email input
        self.emailInput = QLineEdit()
        self.emailInput.setPlaceholderText("e-mail")
        self.emailInput.setFixedSize(300, 40)  # Set fixed size (width, height)
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

        # Password input
        self.passwordInput = QLineEdit()
        self.passwordInput.setPlaceholderText("password")
        self.passwordInput.setFixedSize(300, 40)  # Set fixed size (width, height)
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

        # Login button
        self.loginButton = QPushButton('Log In')
        self.loginButton.setFixedSize(300, 40)  # Set fixed size (width, height)
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

        # Spacer item to create space between the "Log In" and "Register" buttons
        spacerItem = QWidget()
        spacerItem.setFixedSize(300, 20)  # (width, height) of the spacer item

        # Register button
        self.registerButton = QPushButton('Register')
        self.registerButton.setFixedSize(300, 40)  # Set fixed size (width, height)
        self.registerButton.setStyleSheet("""
            QPushButton {
                background-color: #28a745;  /* A green color for the register button */
                color: white;  /* Ensure high contrast text color */
                border: 1px solid #28a745;  /* Same color border as the background */
                border-radius: 0px;
                padding: 10px 20px;
                font-size: 18px;
            }
            QPushButton:hover {
                background-color: #34d058;  /* A lighter green color for the hover state */
            }
        """)
        self.registerButton.clicked.connect(self.on_register_button_clicked)

        # Add widgets to the container
        inputContainer.addWidget(self.emailInput)
        inputContainer.addWidget(self.passwordInput)
        inputContainer.addWidget(self.loginButton)
        inputContainer.addWidget(spacerItem)  # Add the spacer item for extra space
        inputContainer.addWidget(self.registerButton)  # Add the register button to the layout
        inputContainer.addStretch(1)

        # Layout to include some padding on the left side
        paddedLayout = QHBoxLayout()
        paddedLayout.addLayout(inputContainer)
        paddedLayout.addStretch()

        # Add the layout with padding to the main layout
        mainLayout.addLayout(paddedLayout)
        mainLayout.addStretch(1)  # Pushes everything to the left

        self.setLayout(mainLayout)


    def on_login_button_clicked(self):
        # Placeholder function for logging in logic
        print("Login button clicked")
        self.hide()  # Hide the login window
        self.dashboard = DashboardWindow()  # Create an instance of the DashboardWindow
        self.dashboard.show()  # Show the dashboard

    def centerWindow(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def on_register_button_clicked(self):
        self.register_window = RegisterWindow()  # Create the Register window
        self.register_window.show()  # Show the Register window
        self.hide()

def main():
    app = QApplication(sys.argv)
    login = LoginWindow()  # Start with the Login window
    login.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

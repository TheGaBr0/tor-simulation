from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel, QLineEdit, QHBoxLayout
from PyQt6.QtGui import QTextCursor
from PyQt6.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot
import logging


class NodeTerminal(QWidget):
    """Terminal widget for nodes: 
       - Log-only for normal nodes
       - Log + commands for exit nodes
    """

    def __init__(self, node):
        super().__init__()
        self.node = node
        self.node_id = node.id
        self.logger = node.logger
        self.node_type = node.type  # 🔹 relay, guard, exit, etc.
        self.compromised = node.compromised

        self.setWindowTitle(f"Node Terminal - {node.id}")
        self.resize(700, 500)

        layout = QVBoxLayout()

        # Header
        header = QLabel(f"Logs: {node.id} ({node.type})")
        header.setStyleSheet("font-size: 12pt; font-weight: bold; padding: 5px;")
        layout.addWidget(header)

        # Log area
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Courier New', monospace;
                font-size: 10pt;
                border: 1px solid #3e3e3e;
            }
        """)
        layout.addWidget(self.output)

        # If exit node, add input field
        if self.node_type == "exit":
            input_layout = QHBoxLayout()
            self.prompt_label = QLabel(f"{node.id}> ")
            self.prompt_label.setStyleSheet("color: #00ff00; font-family: 'Courier New', monospace;")
            input_layout.addWidget(self.prompt_label)

            self.input = QLineEdit()
            self.input.setStyleSheet("""
                QLineEdit {
                    background-color: #2d2d2d;
                    color: #d4d4d4;
                    font-family: 'Courier New', monospace;
                    font-size: 10pt;
                    border: 1px solid #3e3e3e;
                    padding: 5px;
                }
            """)
            input_layout.addWidget(self.input)
            layout.addLayout(input_layout)

            # Connect input to process commands
            self.input.returnPressed.connect(self.process_command)

        self.setLayout(layout)

        # Setup logging handler
        handler = NodeTerminalHandler(self)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        self.logger.handlers.clear()
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        self.append_log(f"--- Log terminal started for {node.id} ({node.type}) ---")

        if self.node_type == "exit" and self.compromised:
            self.append_log("Type 'redirect <ip> <port>' to redirect exit traffic")

    @pyqtSlot(str)
    def append_log(self, message: str):
        self.output.append(message)
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output.setTextCursor(cursor)

    def process_command(self):
        """Handle commands only for exit nodes"""
        if self.node_type != "exit" or not self.compromised:
            return

        input_text = self.input.text().strip()
        self.input.clear()
        if not input_text:
            return

        parts = input_text.split()
        command = parts[0].lower()
        args = parts[1:]

        if command == "redirect":
            if len(args) != 2:
                self.append_log("Usage: redirect <server_ip> <server_port>")
                return
            server_ip, server_port = args
            self.append_log(f"[Exit {self.node_id}] Redirecting traffic to {server_ip}:{server_port}")
            
            self.node.set_exit_redirection(not self.node.redirection, server_ip, int(server_port))

        elif command == "help":
            self.append_log("Available commands (exit only):")
            self.append_log("  redirect <ip> <port>  - Redirect exit traffic")
            self.append_log("  help                  - Show this help message")

        else:
            self.append_log(f"Unknown command: {command}")

    def closeEvent(self, event):
        for handler in self.logger.handlers[:]:
            if isinstance(handler, NodeTerminalHandler):
                self.logger.removeHandler(handler)
        event.accept()


class NodeTerminalHandler(logging.Handler):
    """Handler for node log output into terminal"""
    def __init__(self, terminal_widget):
        super().__init__()
        self.terminal_widget = terminal_widget

    def emit(self, record):
        try:
            msg = self.format(record)
            QMetaObject.invokeMethod(
                self.terminal_widget,
                "append_log",
                Qt.ConnectionType.QueuedConnection,
                Q_ARG(str, msg)
            )
        except Exception as e:
            print(f"Error in NodeTerminalHandler.emit: {e}")

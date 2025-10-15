from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel, QLineEdit, QHBoxLayout
from PyQt6.QtGui import QTextCursor
from PyQt6.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot
import logging
import threading


class NodeTerminal(QWidget):
    """
    Terminal interface for Tor network nodes.
    Displays logs for all nodes; compromised nodes get additional command functionality.
    """

    def __init__(self, node, dir_server):
        super().__init__()
        self.node = node
        self.node_id = node.id
        self.logger = node.logger
        self.node_type = node.type  # Node role: relay, guard, exit, etc.
        self.compromised = node.compromised
        self.redirection = node.redirection
        self.dir_server = dir_server
        self.setWindowTitle(f"Node Terminal - {node.id}")
        self.resize(700, 500)

        layout = QVBoxLayout()

        # Header displaying node ID and type
        header = QLabel(f"Logs: {node.id} ({node.type})")
        header.setStyleSheet("font-size: 12pt; font-weight: bold; padding: 5px;")
        layout.addWidget(header)

        # Terminal output area with dark theme
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

        # Add command input for compromised nodes only
        if self.compromised:
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

            # Connect enter key to command processor
            self.input.returnPressed.connect(self.process_command)

        self.setLayout(layout)

        # Configure custom logging handler to redirect node logs to this terminal
        handler = NodeTerminalHandler(self)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        self.logger.handlers.clear()
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        # Display initial node information
        self.append_log(f"--- Log terminal started for {node.id} ({node.type}) ---")
        self.append_log(f"--- Listening on {node.ip} {node.port} ---")
        self.append_log(f"--- Bandwidth: {node.band_width}, Uptime: {node.uptime} ---")
        self.append_log(f"--- Owner: {node.owner} ---")

        # Show available attack commands for compromised nodes
        if self.compromised:    
            self.append_log("Type 'flood <server_ip> <server_port>' to flood a server")
            if self.node_type == 'exit':
                self.append_log("Type 'redirect <ip> <port>' to redirect exit traffic")

    @pyqtSlot(str)
    def append_log(self, message: str):
        """
        Append a message to the terminal output.
        Thread-safe via Qt's slot mechanism.
        """
        self.output.append(message)
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output.setTextCursor(cursor)

    def process_command(self):
        """
        Parse and execute commands for compromised nodes.
        Supports traffic redirection and circuit flooding attacks.
        """
        input_text = self.input.text().strip()
        self.input.clear()
        if not input_text:
            return

        parts = input_text.split()
        command = parts[0].lower()
        args = parts[1:]

        if command in ("clear", "cls"):
            # Clear terminal output
            self.output.clear()
            self.append_log(f"--- Console cleared for {self.node_id} ---")
            return

        elif command == "redirect":
            # Toggle traffic redirection (exit nodes only)
            if self.node_type != "exit" or not self.compromised:
                return
            if len(args) != 2:
                self.append_log("Usage: redirect <server_ip> <server_port>")
                return
            server_ip, server_port = args

            if not self.redirection:
                self.append_log(f"[Exit {self.node_id}] Redirecting traffic to {server_ip}:{server_port}")
            else:
                self.append_log(f"[Exit {self.node_id}] No longer redirecting traffic to {server_ip}:{server_port}")
            
            self.redirection = not self.redirection
            self.node._set_exit_redirection(self.redirection, server_ip, int(server_port))

        elif command == "flood":
            # Launch a flooding attack on a target server
            if not self.compromised:
                return
            
            if len(args) != 2:
                self.append_log("Usage: flood <server_ip> <server_port>")
                return
            server_ip, server_port = args

            # Retrieve target's public key from directory server
            pub_key = None
            for node in self.dir_server.guards + self.dir_server.relays + self.dir_server.exits:
                if node.ip == server_ip and node.port == int(server_port):
                    pub_key = node.pub
                    break

            self.append_log(f"[Exit {self.node_id}] Flooding to {server_ip}:{server_port}")

            # Spawn multiple threads to flood the target
            for _ in range(5):
                t = threading.Thread(
                    target=self.node._flood_circuit,
                    args=(server_ip, int(server_port), pub_key),
                    daemon=True  # Thread won't block process termination
                )
                t.start()

        elif command == "help":
            # Display available commands
            self.append_log("Available commands (compromised nodes only):")
            self.append_log("  redirect <ip> <port>  - Toggle exit traffic redirection")
            self.append_log("  flood <ip> <port>     - Launch flooding attack")
            self.append_log("  clear                 - Clear terminal output")
            self.append_log("  help                  - Show this help message")

        else:
            self.append_log(f"Unknown command: {command}")


class NodeTerminalHandler(logging.Handler):
    """
    Custom logging handler that routes node logs to the terminal widget.
    Uses Qt's thread-safe mechanism for GUI updates.
    """
    def __init__(self, terminal_widget):
        super().__init__()
        self.terminal_widget = terminal_widget

    def emit(self, record):
        """
        Emit a log record to the terminal widget.
        Thread-safe via QMetaObject.invokeMethod.
        """
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
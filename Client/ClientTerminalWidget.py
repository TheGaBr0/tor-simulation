from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTextEdit, QLineEdit, 
                             QPushButton, QHBoxLayout, QLabel)
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtCore import Qt, pyqtSignal, QMetaObject, Q_ARG, pyqtSlot, QTimer
import logging
from Attacks.tor_security_sim import *
from Attacks.AttacksThreading import *


class TerminalHandler(logging.Handler):
    """Custom logging handler that emits signals for Qt integration"""
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
            print(f"Error in TerminalHandler.emit: {e}")


class TerminalWidget(QWidget):
    """Terminal widget for displaying client logs and accepting commands"""
    log_signal = pyqtSignal(str)
    
    def __init__(self, client_id, client, analyzer, manager=None, editor=None):
        super().__init__()
        self.client_id = client_id
        self.client = client
        self.manager = manager   # 🔹 now holds reference to EntityConnectionManager
        self.editor = editor
        self.analyzer = analyzer
        
        self.setWindowTitle(f"Terminal - {client_id}")
        self.resize(800, 600)
        
        # --- UI setup (unchanged) ---
        layout = QVBoxLayout()
        
        header = QLabel(f"Client Terminal: {client_id}")
        header.setStyleSheet("font-size: 14pt; font-weight: bold; padding: 5px;")
        layout.addWidget(header)
        
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
        
        input_layout = QHBoxLayout()
        self.prompt_label = QLabel(f"{client_id}> ")
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
        self.setLayout(layout)
        
        # Logging integration
        handler = TerminalHandler(self)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.client.logger.handlers.clear()
        self.client.logger.addHandler(handler)
        self.client.logger.setLevel(logging.INFO)
        self.client.logger.propagate = False
        
        # Connect input
        self.input.returnPressed.connect(self.process_command)
        
        # Initial messages
        self.append_log(f"Terminal initialized for {client_id}")
        self.append_log(f"--- Listening on {client.ip} {client.port} ---")
        self.append_log("Type 'connect <circuit_id>' to establish Tor connection")
        self.append_log("Type 'help' for available commands")
    
    @pyqtSlot(str)
    def append_log(self, message: str):
        """Append a log message to the terminal - thread-safe"""
        self.output.append(message)
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output.setTextCursor(cursor)
    
    def process_command(self):
        """Parse and execute a terminal command"""
        input_text = self.input.text().strip()
        self.input.clear()
        if not input_text:
            return

        parts = input_text.split()
        command = parts[0].lower()
        args = parts[1:]

        if command == "connect":
            if len(args) != 1:
                self.append_log("Usage: connect <circuit_id>")
                return
            try:
                circuit_id = int(args[0])
            except ValueError:
                self.append_log("ERROR: Circuit ID must be an integer")
                return
            if circuit_id not in self.manager.clients[self.client_id]['circuits']:
                self.manager.add_circuit(self.client_id, circuit_id)
            self.append_log(f"Connecting circuit {circuit_id}...")
            QTimer.singleShot(100, lambda: self.manager.connect_client(self.client_id, circuit_id))

        elif command == "destroy":
            if len(args) != 1:
                self.append_log("Usage: destroy <circuit_id>")
                return
            try:
                circuit_id = int(args[0])
            except ValueError:
                self.append_log("ERROR: Circuit ID must be an integer")
                return
            self.append_log(f"Destroying circuit {circuit_id}...")
            QTimer.singleShot(100, lambda: self.manager.destroy_client_circuit(self.client_id, circuit_id))

        elif command == "send":
            if len(args) < 4:
                self.append_log("Usage: send <server_ip> <server_port> <message> <circuit_id>")
                return
            server_ip = args[0]
            try:
                server_port = int(args[1])
                circuit_id = int(args[-1])
            except ValueError:
                self.append_log("ERROR: Port and circuit_id must be integers")
                return
            payload = " ".join(args[2:-1])
            if circuit_id not in self.client.circuits:
                self.manager.add_circuit(self.client_id, circuit_id)
            self.manager.send_message(self.client_id, server_ip, server_port, payload, circuit_id)
            
            self.append_log(f"Sending '{payload}' to {server_ip}:{server_port} via circuit {circuit_id}")
            
            # Show quick correlation update
            update_table = self.analyzer.print_correlation_update()
            print(update_table)

        elif command == "status":
            circuits = getattr(self.client, "circuits", {})
            if not circuits:
                self.append_log("No circuits registered for this client")
                return
            self.append_log("Client circuits status:")
            for cid, node_list in circuits.items():
                if not node_list:
                    self.append_log(f"  Circuit {cid}: empty")
                    continue
                node_ids = [getattr(node, "id", str(node)) for node in node_list]
                status = "connected" if len(node_ids) > 1 else "not connected"
                self.append_log(f"  Circuit {cid}: {status} -> Path: {node_ids}")

        elif command == "clear":
            self.output.clear()
            self.append_log(f"Terminal initialized for {self.client_id}")
            self.append_log("Type 'connect <circuit_id>' to establish Tor connection")
            self.append_log("Type 'help' for available commands")

        elif command == "help":
            self.append_log("Available commands:")
            self.append_log("  connect <circuit_id>                 - Establish connection to Tor network")
            self.append_log("  destroy <circuit_id>                 - Destroy a circuit")
            self.append_log("  send <ip> <port> <msg> <circuit_id> - Send message via circuit")
            self.append_log("  status                               - Show circuits and paths")
            self.append_log("  clear                                - Clear terminal output")
            self.append_log("  help                                 - Show this help message")

        else:
            self.append_log(f"Unknown command: {command}")

    def closeEvent(self, event):
        """Clean up logging handler when terminal closes"""
        for handler in self.client.logger.handlers[:]:
            if isinstance(handler, TerminalHandler):
                self.client.logger.removeHandler(handler)
        event.accept()


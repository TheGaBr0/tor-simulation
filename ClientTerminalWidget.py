from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTextEdit, QLineEdit, 
                             QPushButton, QHBoxLayout, QLabel)
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtCore import Qt, pyqtSignal, QMetaObject, Q_ARG, pyqtSlot, QTimer
import logging


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
    
    def __init__(self, client_id, client):
        super().__init__()
        self.client_id = client_id
        self.client = client
        
        self.setWindowTitle(f"Terminal - {client_id}")
        self.resize(800, 600)
        
        # UI setup
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
        self.input.returnPressed.connect(self.process_command)
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
        
        # Initial messages
        self.append_log(f"Terminal initialized for {client_id}")
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
        """Process user input command"""
        input_text = self.input.text().strip()
        self.input.clear()
        
        if not input_text:
            return
        
        self.append_log(f"{self.client_id}> {input_text}")
        parts = input_text.split()
        cmd = parts[0].lower()
        
        if cmd == "connect":
            if len(parts) != 2:
                self.append_log("Usage: connect <circuit_id>")
                return
            
            try:
                circuit_id = int(parts[1])
            except ValueError:
                self.append_log("ERROR: circuit_id must be an integer")
                return
            
            if not hasattr(self.client, "manager"):
                self.append_log("ERROR: Client not linked to a manager")
                return
            
            client_info = self.client.manager.clients.get(self.client_id)
            if not client_info:
                self.append_log(f"Client {self.client_id} not registered in manager")
                return
            
            # Add circuit dynamically if missing
            if circuit_id not in client_info['circuits']:
                self.client.manager.add_circuit(self.client_id, circuit_id)
            
            circuit_info = client_info['circuits'][circuit_id]
            if circuit_info['connected']:
                self.append_log(f"Circuit {circuit_id} is already connected")
                return
            
            self.append_log(f"Scheduling connection for circuit {circuit_id}...")
            QTimer.singleShot(
                100, 
                lambda cid=self.client_id, circ=circuit_id: self.client.manager.connect_client(cid, circ)
            )
        
        elif cmd == "send":
            if len(parts) < 5:
                self.append_log("Usage: send <ip> <port> <message> <circuit_id>")
                return
            server_ip = parts[1]
            try:
                server_port = int(parts[2])
                circuit_id = int(parts[-1])
                payload = " ".join(parts[3:-1])
            except ValueError:
                self.append_log("ERROR: port and circuit_id must be integers")
                return
            
            if hasattr(self.client, "manager"):
                self.client.manager.send_message(
                    self.client_id, server_ip, server_port, payload, circuit_id
                )
                self.append_log(f"Sending '{payload}' to {server_ip}:{server_port} via circuit {circuit_id}")
            else:
                self.append_log("ERROR: No manager linked to client")
        
        elif cmd == "status":
            client_info = getattr(self.client, "manager", None)
            if client_info is None:
                self.append_log("ERROR: No manager linked to client")
                return
            self.append_log("Client circuits status:")
            client_data = self.client.manager.clients.get(self.client_id, {})
            circuits = client_data.get('circuits', {})
            if not circuits:
                self.append_log("  No circuits registered")
            for cid, info in circuits.items():
                status = "connected" if info['connected'] else "not connected"
                self.append_log(f"  Circuit {cid}: {status}")
        
        elif cmd == "clear":
            self.output.clear()
            self.append_log(f"Terminal initialized for {self.client_id}")
            self.append_log("Type 'connect <circuit_id>' to establish Tor connection")
            self.append_log("Type 'help' for available commands")
        
        elif cmd == "help":
            self.append_log("Available commands:")
            self.append_log("  connect <circuit_id>       - Establish connection to Tor network")
            self.append_log("  send <ip> <port> <msg> <circuit_id> - Send message via circuit")
            self.append_log("  status                     - Show connection status")
            self.append_log("  clear                      - Clear terminal output")
            self.append_log("  help                       - Show this help message")
        
        else:
            self.append_log(f"Unknown command: {cmd}")
    
    def closeEvent(self, event):
        """Clean up logging handler when terminal closes"""
        for handler in self.client.logger.handlers[:]:
            if isinstance(handler, TerminalHandler):
                self.client.logger.removeHandler(handler)
        event.accept()

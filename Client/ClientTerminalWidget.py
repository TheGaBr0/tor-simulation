from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTextEdit, QLineEdit, 
                             QPushButton, QHBoxLayout, QLabel)
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtCore import Qt, pyqtSignal, QMetaObject, Q_ARG, pyqtSlot, QTimer
import logging
from Attacks.Correlation_Inference import *
from Attacks.AttacksThreading import *


class TerminalHandler(logging.Handler):
    """
    Custom logging handler that integrates with PyQt6's signal/slot mechanism.
    This allows log messages to be safely displayed in the GUI from any thread.
    """
    def __init__(self, terminal_widget):
        super().__init__()
        self.terminal_widget = terminal_widget
        
    def emit(self, record):
        """
        Emit a log record to the terminal widget using Qt's thread-safe method invocation.
        This ensures that GUI updates happen on the main thread.
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
            print(f"Error in TerminalHandler.emit: {e}")


class TerminalWidget(QWidget):
    """
    Terminal interface for interacting with Tor clients.
    Displays real-time logs and accepts user commands for circuit management.
    """
    log_signal = pyqtSignal(str)
    
    def __init__(self, client_id, client, analyzer, manager=None, editor=None):
        super().__init__()
        self.client_id = client_id
        self.client = client
        self.manager = manager  # Reference to EntityConnectionManager for circuit operations
        self.editor = editor
        self.analyzer = analyzer
        
        self.setWindowTitle(f"Terminal - {client_id}")
        self.resize(800, 600)
        
        # Setup the terminal UI layout
        layout = QVBoxLayout()
        
        # Header showing which client this terminal belongs to
        header = QLabel(f"Client Terminal: {client_id}")
        header.setStyleSheet("font-size: 14pt; font-weight: bold; padding: 5px;")
        layout.addWidget(header)
        
        # Terminal output area with dark theme styling
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
        
        # Command input area with prompt
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
        
        # Setup custom logging handler to redirect client logs to this terminal
        handler = TerminalHandler(self)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.client.logger.handlers.clear()
        self.client.logger.addHandler(handler)
        self.client.logger.setLevel(logging.INFO)
        self.client.logger.propagate = False
        
        # Connect enter key to command processing
        self.input.returnPressed.connect(self.process_command)
        
        # Display welcome message and basic info
        self.append_log(f"Terminal initialized for {client_id}")
        self.append_log(f"--- Listening on {client.ip} {client.port} ---")
        self.append_log("Type 'connect <circuit_id>' to establish Tor connection")
        self.append_log("Type 'help' for available commands")
    
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
        Parse and execute user commands entered in the terminal.
        Supports circuit management and message sending operations.
        """
        input_text = self.input.text().strip()
        self.input.clear()
        if not input_text:
            return

        parts = input_text.split()
        command = parts[0].lower()
        args = parts[1:]

        if command == "connect":
            # Establish a new Tor circuit
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
            # Use QTimer to avoid blocking the GUI thread
            QTimer.singleShot(100, lambda: self.manager.connect_client(self.client_id, circuit_id))

        elif command == "destroy":
            # Tear down an existing circuit
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
            # Send a message through a Tor circuit to a destination server
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
            
            # Create circuit if it doesn't exist yet
            if circuit_id not in self.client.circuits:
                self.manager.add_circuit(self.client_id, circuit_id)
            
            self.manager.send_message(self.client_id, server_ip, server_port, payload, circuit_id)
            self.append_log(f"Sending '{payload}' to {server_ip}:{server_port} via circuit {circuit_id}")
            
            # Display correlation analysis update (for attack demonstration)
            update_table = self.analyzer.print_correlation_update()
            print(update_table)

        elif command == "status":
            # Show current state of all circuits for this client
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
            # Clear the terminal output
            self.output.clear()
            self.append_log(f"Terminal initialized for {self.client_id}")
            self.append_log("Type 'connect <circuit_id>' to establish Tor connection")
            self.append_log("Type 'help' for available commands")

        elif command == "help":
            # Display available commands
            self.append_log("Available commands:")
            self.append_log("  connect <circuit_id>                 - Establish connection to Tor network")
            self.append_log("  destroy <circuit_id>                 - Destroy a circuit")
            self.append_log("  send <ip> <port> <msg> <circuit_id> - Send message via circuit")
            self.append_log("  status                               - Show circuits and paths")
            self.append_log("  clear                                - Clear terminal output")
            self.append_log("  help                                 - Show this help message")

        else:
            self.append_log(f"Unknown command: {command}")

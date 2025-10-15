from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel
from PyQt6.QtGui import QTextCursor
from PyQt6.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot
import logging


class ServerTerminal(QWidget):
    """
    Read-only terminal interface for destination servers.
    Displays incoming connection logs and message activity.
    """

    def __init__(self, logger, server):
        super().__init__()
        self.server_id = server.id
        self.logger = server.logger
        self.compromised = server.compromised
        self.server_ip = server.ip
        self.server_port = server.port

        self.setWindowTitle(f"Server Terminal - {server.id}")
        self.resize(700, 500)

        layout = QVBoxLayout()

        # Header displaying server identifier
        header = QLabel(f"Server Logs: {server.id}")
        header.setStyleSheet("font-size: 12pt; font-weight: bold; padding: 5px;")
        layout.addWidget(header)

        # Log display area with dark theme styling
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

        self.setLayout(layout)

        # Configure custom logging handler to redirect server logs to this terminal
        handler = ServerTerminalHandler(self)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        self.logger.handlers.clear()
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        # Display initial server information and usage hints
        self.append_log(f"--- Server terminal started for {server.id} ---")

        if not self.compromised:
            self.append_log(f"To send a message to this server -> send {server.ip} {server.port} <message> <circuit_id>")
        else:
            self.append_log(f"This server is compromised - use exit node commands to redirect traffic here")
            self.append_log(f"Command: redirect {server.ip} {server.port}")

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


class ServerTerminalHandler(logging.Handler):
    """
    Custom logging handler that routes server logs to the terminal widget.
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
            print(f"Error in ServerTerminalHandler.emit: {e}")
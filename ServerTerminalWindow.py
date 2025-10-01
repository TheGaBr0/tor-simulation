from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel
from PyQt6.QtGui import QTextCursor
from PyQt6.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot
import logging

class ServerTerminal(QWidget):
    """Log terminal widget for servers"""

    def __init__(self, server_id, logger):
        super().__init__()
        self.server_id = server_id
        self.logger = logger

        self.setWindowTitle(f"Server Terminal - {server_id}")
        self.resize(700, 500)

        layout = QVBoxLayout()

        # Header
        header = QLabel(f"Server Logs: {server_id}")
        header.setStyleSheet("font-size: 12pt; font-weight: bold; padding: 5px;")
        layout.addWidget(header)

        # Log display
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

        # Setup logging handler
        handler = ServerTerminalHandler(self)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        self.logger.handlers.clear()
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        self.append_log(f"--- Server terminal started for {server_id} ---")

    @pyqtSlot(str)
    def append_log(self, message: str):
        """Append a log message in a thread-safe way"""
        self.output.append(message)
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output.setTextCursor(cursor)

    def closeEvent(self, event):
        """Clean up logging handlers on close"""
        for handler in self.logger.handlers[:]:
            if isinstance(handler, ServerTerminalHandler):
                self.logger.removeHandler(handler)
        event.accept()


class ServerTerminalHandler(logging.Handler):
    """Logging handler for server terminal"""
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
            print(f"Error in ServerTerminalHandler.emit: {e}")

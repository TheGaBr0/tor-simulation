import threading
import socket
import logging
from typing import Optional, Dict
from Utils.Cryptograpy_utils import *
import json
from TorNetwork.TorMessage import *

RECORDS = {
    "alpha": "Record A",
    "beta": "Record B",
    "gamma": "Record C"
}

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] (%(name)s) %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

class Server:
    def __init__(self, server_id: str, ip: str, port: int, oracle, compromised: bool):
        self.id = server_id
        self.ip = ip

        # Socket and threading
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.compromised = compromised

        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.connections: Dict[str, socket.socket] = {}
        
        self.logger = logging.getLogger(f"Server-{self.id}")

        oracle.add_symb_ip(self.ip, self.port)


    def start(self):
        """Start the server and begin listening for connections."""
        if self.running:
            self.logger.warning("Server already running.")
            return
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
            self.server_thread.start()
            
            status = "COMPROMISED" if self.compromised else "NORMAL"
            self.logger.info(f"Server {self.id} started on {self.bind_ip}:{self.port} ({status})")
            self.logger.debug(f"Public IP: {self.ip} — Listening for incoming connections.")
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}", exc_info=True)
            self.stop()

    def stop(self):
        """Stop the server."""
        self.logger.info("Stopping server...")
        self.running = False
        
        for conn in self.connections.values():
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except Exception:
                pass
        self.connections.clear()
        
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.server_socket.close()
            except Exception as e:
                self.logger.debug(f"Error closing server socket: {e}")
            finally:
                self.server_socket = None

        if hasattr(self, 'server_thread') and self.server_thread.is_alive():
            self.logger.debug("Waiting for server thread to terminate...")
            self.server_thread.join(timeout=2.0)
            if self.server_thread.is_alive():
                self.logger.warning("Server thread did not terminate in time.")
        
        self.logger.info("Server stopped successfully.")
    
    def _server_loop(self):
        """Main server loop — accepts incoming connections."""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, addr = self.server_socket.accept()
                client_id = f"{addr[0]}:{addr[1]}"
                self.logger.info(f"Accepted connection from {client_id}")
                
                client_thread = threading.Thread(
                    target=self._handle_client, 
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error in server loop: {e}", exc_info=True)

    def _handle_client(self, client_socket: socket.socket, addr):
        """Handle an individual client connection."""
        client_id = f"{addr[0]}:{addr[1]}"
        self.logger.debug(f"Started client handler for {client_id}")
        
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    self.logger.info(f"Client {client_id} disconnected.")
                    break
                
                if not self.compromised:
                    self.logger.debug(f"Received {len(data)} bytes from {client_id} (normal server).")
                    response = self._process_message(data)
                else:
                    self.logger.debug(f"Received {len(data)} bytes from {client_id} (compromised server).")
                    response = self._process_message_attacker(data)

                client_socket.sendall(response)
                self.logger.debug(f"Sent {len(response)} bytes back to {client_id}")
    
        except socket.timeout:
            self.logger.warning(f"Timeout while handling client {client_id}")
        except Exception as e:
            self.logger.error(f"Error while handling client {client_id}: {e}", exc_info=True)
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            self.logger.debug(f"Connection closed for {client_id}")

    def _process_message(self, data):
        """Process message for normal server."""
        try:
         
            requested_key = decode_payload(data, 1)[0].decode('utf-8')
            self.logger.info(f"Received key request: '{requested_key}'")

            record = RECORDS.get(requested_key)
            if record:
                self.logger.info(f"Found record for '{requested_key}': {record}")
            else:
                self.logger.warning(f"Key '{requested_key}' not found.")
                record = f"Error: Key '{requested_key}' not found."

            encoded = data_to_bytes(record)
            self.logger.debug(f"Encoded response size: {len(encoded)} bytes.")
            return encoded

        except Exception as e:
            self.logger.error(f"Error processing message: {e}", exc_info=True)
            return data_to_bytes("Internal server error")

    def _process_message_attacker(self, data):
        """Process message for compromised server."""
        try:
            requested_key = "<undecodable>"
            try:
                requested_key = decode_payload(data, 1)[0].decode('utf-8')
            except Exception:
                pass

            self.logger.info(f"[MALICIOUS] Received key: '{requested_key}'. Sending fake data.")
            malicious_response = "Bad code"
            encoded = data_to_bytes(malicious_response)
            self.logger.debug(f"[MALICIOUS] Encoded payload size: {len(encoded)} bytes.")
            return encoded

        except Exception as e:
            self.logger.error(f"[MALICIOUS] Error crafting malicious response: {e}", exc_info=True)
            return data_to_bytes("Bad code")

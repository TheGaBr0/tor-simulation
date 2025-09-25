import threading
import socket
import logging
from typing import Optional, Dict
import json
from TorMessage import *

class Server:
    def __init__(self, server_id: str, ip: str, port: int):
        self.id = server_id
        self.ip = ip

        # Socket e threading
        self.bind_ip = "127.0.0.1"
        self.port = port

        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.connections: Dict[str, socket.socket] = {}
        
        self.logger = logging.getLogger(f"Server-{self.id}")

    def start(self):
        """Avvia il server - inizia ad ascoltare per connessioni"""
        if self.running:
            self.logger.warning("Server già attivo")
            return
        
        try:
            # Crea socket server
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            # Avvia thread server
            self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
            self.server_thread.start()
            
            self.logger.info(f"Server avviato su {self.bind_ip}:{self.port} (IP pubblico: {self.ip})")
            
        except Exception as e:
            self.logger.error(f"Errore nell'avvio del server: {e}")
            self.stop()

    def stop(self):
        """Ferma il server"""
        self.running = False
        
        # Chiudi tutte le connessioni
        for conn in self.connections.values():
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except:
                pass
        self.connections.clear()
        
        # Chiudi server socket
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)  
                self.server_socket.close()
            except Exception as e:
                self.logger.debug(f"Errore chiusura server socket: {e}")
            finally:
                self.server_socket = None

        if hasattr(self, 'server_thread') and self.server_thread.is_alive():
            self.logger.debug("Aspettando terminazione server thread...")
            self.server_thread.join(timeout=2.0)
            if self.server_thread.is_alive():
                self.logger.warning("Server thread non terminato entro timeout")
        
        self.logger.info("Server fermato")
    
    def _server_loop(self):
        """Loop principale del server - accetta connessioni"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)  # Timeout per permettere shutdown
                client_socket, addr = self.server_socket.accept()
                
                # Gestisci connessione in thread separato
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
                    self.logger.error(f"Errore nel server loop: {e}")

    def _handle_client(self, client_socket: socket.socket, addr):
        """Gestisce una connessione client"""
        client_id = f"{addr[0]}:{addr[1]}"
        self.logger.info(f"Nuova connessione da {client_id}")
        
        try:
            # Set timeout for client socket
            client_socket.settimeout(10.0)
            
            # Ricevi dati
            data = client_socket.recv(4096)
            if not data:
                self.logger.warning(f"Nessun dato ricevuto da {client_id}")
                return
                
            self.logger.info(f"Ricevuto messaggio raw: {data.decode('utf-8')} da {client_id}")
            
            response_payload = {
                "payload": "culoncazzo",
            }
            
            response_data = json.dumps(response_payload).encode('utf-8')
            
            # Invia risposta
            client_socket.sendall(response_data)
            self.logger.info(f"Risposta inviata a {client_id}: {response_payload}")
    
        
        except socket.timeout:
            self.logger.error(f"Timeout gestione client {client_id}")
        except Exception as e:
            self.logger.error(f"Errore gestione client {client_id}: {e}")
        finally:
            # Chiudi sempre la connessione
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
                self.logger.info(f"Connessione chiusa con {client_id}")
            except Exception as e:
                self.logger.debug(f"Errore chiusura connessione con {client_id}: {e}")
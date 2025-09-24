from Cryptograpy_utils import gen_rsa_keypair, rsa_decrypt, process_dh_handshake_response
import threading
import socket
import logging
from typing import Optional, Dict
import json
from TorMessage import TorMessage
import base64

# Larghezza di banda rappresentata dai valori: 0: bassa, 1. media, 2:alta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class Node:
    def __init__(self, node_id: str, node_type: str, ip_address: str, band_width: int ,
                 owner: str, port: int, compromise: bool = False):
        self.id = node_id
        self.ip = ip_address
        self.type = node_type  # guard/relay/exit
        self._priv, self.pub = gen_rsa_keypair()

        self.compromised = compromise
        self.band_width = band_width
        self.owner = owner

        self.K1 = None

        # Socket e threading
        self.bind_ip = "127.0.0.1"
        self.port = port

        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.connections: Dict[str, socket.socket] = {}
        
        # Routing table - mappa destination -> next_hop
        self.routing_table: Dict[str, tuple] = {}  # destination_id -> (ip, port)
        
        self.logger = logging.getLogger(f"Nodo-{self.id}")

    def __str__(self):
        """Restituisce una rappresentazione stringa leggibile del nodo"""
        bandwidth_labels = {0: "bassa", 1: "media", 2: "alta"}
        bandwidth_str = bandwidth_labels.get(self.band_width, "sconosciuta")
        
        status = "attivo" if self.running else "inattivo"
        compromise_str = "compromesso" if self.compromised else "sicuro"
        
        return (f"Node(id='{self.id}', type='{self.type}', "
                f"ip='{self.ip}:{self.port}', bandwidth='{bandwidth_str}', "
                f"owner='{self.owner}', status='{status}', security='{compromise_str}')")
    
    def start(self):
        """Avvia il nodo - inizia ad ascoltare per connessioni"""
        if self.running:
            self.logger.warning("Nodo già attivo")
            return
        
        try:
            # Crea socket server
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            # Avvia thread server
            self.server_thread = threading.Thread(target=self._node_loop, daemon=True)
            self.server_thread.start()
            
            self.logger.info(f"Nodo avviato su {self.bind_ip}:{self.port} (IP pubblico: {self.ip})")
            
        except Exception as e:
            self.logger.error(f"Errore nell'avvio del nodo: {e}")
            self.stop()

    def stop(self):
        """Ferma il nodo"""
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
                self.running = False

        if hasattr(self, 'server_thread') and self.server_thread.is_alive():
            self.logger.debug("Aspettando terminazione server thread...")
            self.server_thread.join(timeout=2.0)
        if self.server_thread.is_alive():
            self.logger.warning("Server thread non terminato entro timeout")
        
        self.logger.info("Nodo fermato")
    
    def _node_loop(self):
        """Loop principale del nodo - accetta connessioni"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)  # Timeout per permettere shutdown
                client_socket, addr = self.server_socket.accept()
                
                # Gestisci connessione in thread separato
                client_thread = threading.Thread(
                    target=self._handle_connection, 
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Errore nel server loop: {e}")

    def _handle_connection(self, client_socket: socket.socket, addr):
        """Gestisce una connessione"""
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
                            
            response_data = self._process_message(data)
        

            client_socket.sendall(response_data)

            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
        
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

    def _process_message(self, data):
        """Processa un messaggio ricevuto"""

        try:
            payload_str = data.decode("utf-8")
            payload = json.loads(payload_str)

            match payload.get("cmd"):
                case "CREATE":

                    self.logger.info(f"Richiesta CREATE ricevuta")

                    decrypted_secret = rsa_decrypt(self._priv, base64.b64decode(payload["payload"]))
                    
                    y1, g_y1, H_K1, K1 = process_dh_handshake_response(decrypted_secret)
                    

                    self.K1 = K1

                    # Converti g_y1 in bytes
                    g_y1_bytes = g_y1.to_bytes((g_y1.bit_length() + 7) // 8, 'big')
                    # Combina con H_K1 usando virgola come separatore
                    combined_payload = len(g_y1_bytes).to_bytes(2, 'big') + g_y1_bytes + H_K1
                    # TorMessage farà automaticamente il base64 encoding

                    response = TorMessage(payload.get("circ_id"), "CREATED", combined_payload)
                    return json.dumps(response.to_dict()).encode('utf-8')
                
                case "RELAY_EXTEND":
                    pass
                case "sticazzi":
                    dest_port = payload.get("dest_port")
                    dest_ip = payload.get("ip")
                    payload = payload.get("payload")
                    self.logger.info(f"→ data = {payload}, dest_port = {dest_port}, ip = {dest_ip}")

                    response_data = self._forward_message("127.0.0.1", dest_port, payload)
                    return response_data

            
            return None

        except Exception as e:
            self.logger.error(f"Errore processando messaggio: {e}")
            return None



    def _forward_message(self, destination_ip: str, port: int, data):
        """Invia un messaggio a un altro nodo"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)  # Timeout di 5 secondi
                sock.connect((destination_ip, port))
                
                message_data = json.dumps(data).encode('utf-8')
                sock.send(message_data)

                data = sock.recv(4096)

                if not data:
                    self.logger.warning(f"Arrivata risposta senza dati dentro")
                    return None
                else:
                    payload_str = data.decode("utf-8")
            
                    self.logger.warning(f"Ricevuta risposta raw:{payload_str}")

                    enc_payload = {
                        "payload": json.loads(payload_str)
                    }

                    bytes_payload = json.dumps(enc_payload).encode('utf-8')

                sock.shutdown(socket.SHUT_RDWR)
                sock.close()

                return bytes_payload

        except Exception as e:
            self.logger.error(f"Errore invio messaggio a {destination_ip}:{port}: {e}")
            raise

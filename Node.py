from Cryptograpy_utils import *
import threading
import socket
import logging
from typing import Optional, Dict
import json
from TorMessage import *
import base64

# Larghezza di banda rappresentata dai valori: 0: bassa, 1. media, 2:alta
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class Node:
    def __init__(self, node_id: str, node_type: str, ip_address: str, band_width: int , owner: str, port: int, compromise: bool = False):
        self.id = node_id
        self.ip = ip_address
        self.type = node_type  # guard/relay/exit
        self._priv, self.pub = gen_rsa_keypair()
        self.compromised = compromise
        self.band_width = band_width
        self.owner = owner
        
        # Socket e threading
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.connections: Dict[str, socket.socket] = {}
        
        # Routing table - mappa destination -> next_hop
        self.routing_table: Dict[str, tuple] = {}  # destination_id -> (ip, port)
        
        # Store session keys for different circuits
        self.circuit_keys: Dict[int, bytes] = {}  # circ_id -> K
        
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
                
            response_data = self._process_message(data, addr)
            if response_data:
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

    def _process_message(self, data, sender_addr=None):
        """Processa un messaggio ricevuto"""
        try:
            # Decode JSON to get a TorCell object
            payload_str = data.decode("utf-8")
            cell = TorCell.from_json(payload_str)
            
            # --- Handle CREATE ---
            if isinstance(cell, CreateCell) and cell.command == "CREATE":
                self.logger.info("Richiesta CREATE ricevuta")
                g_x1_bytes_decrypted = rsa_decrypt(self._priv, cell.payload)
                y1, g_y1, H_K1, K1 = process_dh_handshake_response(g_x1_bytes_decrypted)
                
                # Store the session key for this circuit
                self.circuit_keys[cell.circ_id] = K1
                self.K = K1  # Keep for backward compatibility
                
                g_y1_bytes = g_y1.to_bytes((g_y1.bit_length() + 7) // 8, 'big')
                combined_payload = len(g_y1_bytes).to_bytes(2, 'big') + g_y1_bytes + H_K1
                
                created_cell = CreatedCell(
                    circ_id=cell.circ_id,
                    payload=combined_payload
                )
                return created_cell.to_json().encode("utf-8")
                
            elif isinstance(cell, CreatedCell) and cell.command == "CREATED":
                self.logger.info("Risposta CREATED ricevuta")
                temp_payload = cell.payload
                length = int.from_bytes(temp_payload[:2], 'big')
                g_y1_bytes = temp_payload[2:2+length]
                H_K_TO_BE_FORWARDED = temp_payload[2+length:]
                
                g_y1 = int.from_bytes(g_y1_bytes, 'big')
                payload_to_be_forwarded = len(g_y1_bytes).to_bytes(2, 'big') + g_y1_bytes + H_K_TO_BE_FORWARDED
                
                # Use the stored session key for this circuit
                K = self.circuit_keys.get(cell.circ_id, self.K)
                payload_to_be_forwarded_encrypted, _ = aes_ctr_encrypt(payload_to_be_forwarded, K, "backward")
                
                relay_header = RelayHeader(
                    relay_command="RELAY_EXTENDED",  # RELAY_EXTENDED
                    stream_id=0,
                    digest=calculate_digest(self.K), #dummy value, client non deve controllarlo credo
                    length=len(payload_to_be_forwarded_encrypted)
                )
                
                relay_response = RelayCell(
                    circ_id=cell.circ_id,
                    relay_header=relay_header,
                    relay_payload=payload_to_be_forwarded_encrypted
                )
                
                return relay_response.to_json().encode("utf-8")
                
            # --- Handle RELAY_EXTEND ---
            elif isinstance(cell, RelayCell) and cell.relay_header.relay_command == "RELAY_EXTEND":
                self.logger.info("Richiesta RELAY_EXTEND ricevuta")
                
                # Use the stored session key for this circuit
                K = self.circuit_keys.get(cell.circ_id, self.K)
                payload_decrypted_K = aes_ctr_decrypt(cell.relay_payload, K, "forward")
                combined_payload = payload_decrypted_K
                
                # Extract length of encrypted g_x1
                length = int.from_bytes(combined_payload[:2], 'big')
                # Extract encrypted g_x1
                g_x1_bytes_encrypted = combined_payload[2:2+length]
                # Extract IP (4 bytes) – it's right before the last 2 bytes (port)
                ip_bytes = combined_payload[2+length:2+length+4]
                ip_str = '.'.join(map(str, ip_bytes))
                # Extract port (2 bytes) – last 2 bytes
                port_bytes = combined_payload[-2:]
                port = int.from_bytes(port_bytes, 'big')
                
                if cell.relay_header.digest == calculate_digest(K):
                    # Forward CREATE to the next node
                    create_cell = CreateCell(
                        circ_id=2,  # circuit ID, choose an appropriate number
                        payload=g_x1_bytes_encrypted  # payload for the CREATE cell
                    )
                    
                    # Forward and wait for response
                    response_data = self._forward_message("127.0.0.1", port, create_cell.to_json().encode("utf-8"))
                    if response_data:
                        # Process the CREATED response and forward it back
                        return self._process_message(response_data)
                    else:
                        self.logger.error("No response from forwarded CREATE")
                        return None
                else:
                    self.logger.warning("Invalid digest in RELAY_EXTEND")
                    return None
                    
            return None
            
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
            return None

    def _forward_message(self, destination_ip: str, port: int, data):
        """Invia un messaggio a un altro nodo"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)  # Timeout di 5 secondi
                sock.connect((destination_ip, port))
                sock.send(data)
                
                # Wait for response
                response_data = sock.recv(1000000)
                if not response_data:
                    self.logger.warning(f"No response data received from {destination_ip}:{port}")
                    return None
                else:
                    return response_data
                    
        except Exception as e:
            self.logger.error(f"Errore invio messaggio a {destination_ip}:{port}: {e}")
            return None
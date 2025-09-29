from Cryptograpy_utils import *
import threading
import socket
import logging
from typing import Optional, Dict
import ipaddress
import json
from TorMessage import *
import base64
from RoutingEntry import RoutingEntry

# Larghezza di banda rappresentata dai valori: 0: bassa, 1. media, 2:alta
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class Node:
    def __init__(self, node_id: str, node_type: str, ip_address: str, band_width: int, 
                 owner: str, port: int, compromise: bool = False):
        self.id = node_id
        self.ip = ip_address
        self.type = node_type
        self._priv, self.pub = gen_rsa_keypair()
        self.compromised = compromise
        self.band_width = band_width
        self.owner = owner
        
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.routing_table: List[RoutingEntry] = []

        self.persistent_connections: Dict[str, socket.socket] = {}
        self.circuit_stream_socket_map: Dict[(int, int), socket.socket] = {}
        
        self.logger = logging.getLogger(f"Nodo-{self.id}")

    def __str__(self):
        bandwidth_labels = {0: "bassa", 1: "media", 2: "alta"}
        return (f"Node(id='{self.id}', type='{self.type}', ip='{self.ip}:{self.port}', "
                f"bandwidth='{bandwidth_labels.get(self.band_width, 'sconosciuta')}', "
                f"owner='{self.owner}', status='{'attivo' if self.running else 'inattivo'}', "
                f"security='{'compromesso' if self.compromised else 'sicuro'}')")

    def start(self):
        if self.running:
            self.logger.warning("Nodo già attivo")
            return
            
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            self.server_thread = threading.Thread(target=self._node_loop, daemon=True)
            self.server_thread.start()
            
            self.logger.info(f"Nodo avviato su {self.bind_ip}:{self.port} (IP pubblico: {self.ip})")
        except Exception as e:
            self.logger.error(f"Errore nell'avvio del nodo: {e}")
            self.stop()

    def stop(self):
        self.running = False

        for conn in self.persistent_connections.values():
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except:
                pass
        self.persistent_connections.clear()
    
        
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.server_socket.close()
            except Exception as e:
                self.logger.debug(f"Errore chiusura server socket: {e}")
            finally:
                self.server_socket = None
                
        if hasattr(self, 'server_thread') and self.server_thread.is_alive():
            self.server_thread.join(timeout=2.0)
            if self.server_thread.is_alive():
                self.logger.warning("Server thread non terminato entro timeout")
                
        self.logger.info("Nodo fermato")

    def _node_loop(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                
                client_thread = threading.Thread(target=self._handle_connection, 
                                                args=(client_socket, addr), daemon=True)
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Errore nel server loop: {e}")

    def _handle_connection(self, client_socket: socket.socket, addr):
        client_id = f"{addr[0]}:{addr[1]}"
        self.logger.info(f"Nuova connessione da {client_id}")
        
        self.persistent_connections[client_id] = client_socket

        try:
            while self.running:  # MODIFICA: loop per mantenere connessione aperta
                data = client_socket.recv(4096)
                
                if not data:
                    self.logger.info(f"Client {client_id} ha chiuso la connessione")
                    break
                    
                response_data = self._process_message(data, addr[0], addr[1])
                if response_data:
                    client_socket.sendall(response_data)
                
        except socket.timeout:
            self.logger.error(f"Timeout gestione client {client_id}")
        except Exception as e:
            self.logger.error(f"Errore gestione client {client_id}: {e}")
        finally:
            if client_id in self.persistent_connections:
                del self.persistent_connections[client_id]
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
                self.logger.info(f"Connessione chiusa con {client_id}")
            except Exception as e:
                self.logger.debug(f"Errore chiusura connessione con {client_id}: {e}")

    def _process_message(self, data, ip, port):
        try:
            
            cell = TorCell.from_bytes(data)
                
            if cell.cmd == TorCommands.CREATE:
                return self._handle_create(cell, ip, port)
            elif cell.cmd == TorCommands.CREATED:
                return self._handle_created(cell, port)
            elif cell.cmd == TorCommands.RELAY:
                return self._handle_relay(cell, ip, port)
                
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
        return None

    def _handle_create(self, cell, ip, port):
        self.logger.info("Cella CREATE ricevuta")
        
        g_x1_bytes_encrypted = decode_payload(cell.data, 1)[0]
        g_x1_bytes_decrypted = rsa_decrypt(self._priv, g_x1_bytes_encrypted)
        
        y1, g_y1, H_K, K = process_dh_handshake_response(g_x1_bytes_decrypted)
        self.routing_table.append(RoutingEntry(ip, port, int.from_bytes(cell.circid), K))
        
        created_cell = TorCell(circid=int.from_bytes(cell.circid), cmd=TorCommands.CREATED,
                              data=encode_payload([data_to_bytes(g_y1), H_K]))
        return created_cell.to_bytes()

    def _handle_created(self, cell, port):
        self.logger.info("Cella CREATED ricevuta")
        
        decoded_payload = decode_payload(cell.data, 2)
        g_y1_bytes, H_K_TO_BE_FORWARDED = decoded_payload[0], decoded_payload[1]
        
        # Find session key
        K = next(entry.get_session_key() for entry in self.routing_table 
                if entry.get_circuit_id() == int.from_bytes(cell.circid) - 1)
        
        # Encrypt response
        relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.EXTENDED, K, "backward")
        streamid_encrypted, _ = aes_ctr_encrypt(data_to_bytes(0), K, "backward")
        digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(K), K, "backward")
        payload_encrypted, _ = aes_ctr_encrypt(encode_payload([g_y1_bytes, H_K_TO_BE_FORWARDED]), K, "backward")
        
        circuit_id = int.from_bytes(cell.circid) - 1 if port is None else int.from_bytes(cell.circid)
        relay_cell = TorCell(circid=circuit_id, cmd=TorCommands.RELAY, relay=relay_encrypted,
                           streamid=streamid_encrypted, digest=digest_encrypted, data=payload_encrypted)
        return relay_cell.to_bytes()

    def _handle_relay(self, cell, ip, port):
        if port is None:
            return self._handle_relay_backward(cell)
        else:
            return self._handle_relay_forward(cell, ip, port)

    def _handle_relay_backward(self, cell):
        self.logger.info("Cella RELAY ricevuta")
        
        # Find session key and encrypt

        K = next(entry.get_session_key() for entry in self.routing_table 
                if entry.get_circuit_id() == int.from_bytes(cell.circid) - 1)
        
        relay_encrypted, _ = aes_ctr_encrypt(cell.relay, K, "backward")
        streamid_encrypted, _ = aes_ctr_encrypt(cell.stream_id, K, "backward")
        digest_encrypted, _ = aes_ctr_encrypt(cell.digest, K, "backward")
        payload_encrypted, _ = aes_ctr_encrypt(cell.payload, K, "backward")
        
        relay_cell = TorCell(circid=int.from_bytes(cell.circid)-1, cmd=TorCommands.RELAY,
                           relay=relay_encrypted, streamid=streamid_encrypted,
                           digest=digest_encrypted, data=payload_encrypted)
        return relay_cell.to_bytes()

    def _handle_relay_forward(self, cell, ip, port):
        self.logger.info("Cella RELAY ricevuta")
        
        # Find session key and decrypt
        K = next(entry.get_session_key() for entry in self.routing_table 
                if entry.get_circuit_id() == int.from_bytes(cell.circid))
        
        relay_decrypted = aes_ctr_decrypt(cell.relay_command, K, "forward")
        streamid_decrypted = aes_ctr_decrypt(cell.streamid, K, "forward")
        digest_decrypted = aes_ctr_decrypt(cell.digest, K, "forward")
        payload_decrypted = aes_ctr_decrypt(cell.data, K, "forward")
        
        if digest_decrypted == calculate_digest(K):
            self.logger.info("Digest verificato")
            if relay_decrypted == RelayCommands.EXTEND:
                self.logger.info("Cella RELAY EXTEND identificata: inoltro CREATE")
                return self._forward_create(cell, payload_decrypted)
            elif relay_decrypted == RelayCommands.BEGIN:
                self.logger.info("Cella RELAY BEGIN identificata: stabilisco connessione con server")
                return self._connect_to_server(cell.circid, streamid_decrypted, payload_decrypted, ip, port)
            elif relay_decrypted == RelayCommands.DATA:
                self.logger.info("Cella RELAY DATA identificata: inoltro dati a server")

                dst_socket = self.circuit_stream_socket_map.get((int.from_bytes(cell.circid), int.from_bytes(streamid_decrypted)))

                dst_socket.send(payload_decrypted)
                response_data = dst_socket.recv(1000000)

                if response_data:
                    # Encrypt the response for backward transmission
                    relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.DATA, K, "backward")
                    streamid_encrypted, _ = aes_ctr_encrypt(streamid_decrypted, K, "backward")
                    digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(K), K, "backward")
                    payload_encrypted, _ = aes_ctr_encrypt(response_data, K, "backward")
                    
                    # Create RELAY DATA cell with server response
                    data_cell = TorCell(circid=int.from_bytes(cell.circid), cmd=TorCommands.RELAY, 
                                    relay=relay_encrypted, streamid=streamid_encrypted,
                                    digest=digest_encrypted, data=payload_encrypted)
                    return data_cell.to_bytes()
                else:
                    return None
        else:
            self.logger.info("Digest non verificato: inoltro RELAY")
            return self._forward_relay(cell, relay_decrypted, streamid_decrypted, 
                                      digest_decrypted, payload_decrypted)

    def _connect_to_server(self, circuid, streamid, payload, ip, port):

        decoded_payload = decode_payload(payload, 2)

        ip_bytes, port_bytes = decoded_payload[0], decoded_payload[1]

        port = int.from_bytes(port_bytes)
        
        ip_str = str(ipaddress.IPv4Address(ip_bytes))

        response = self._forward_message("127.0.0.1", port, data_to_bytes(12345))

        K = next(entry.get_session_key() for entry in self.routing_table 
                if entry.get_circuit_id() == int.from_bytes(circuid)) #è sempre l'exit quindi non diminuisco circid
                
        streamid_encrypted, _ = aes_ctr_encrypt(streamid, K, "backward")
        digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(K), K, "backward")
        payload_encrypted, _ = aes_ctr_encrypt(response, K, "backward")
        
        if response:
            self.logger.info("Connessione con server stabilita con successo: inoltro RELAY CONNECTED")

            self.circuit_stream_socket_map[(int.from_bytes(circuid), int.from_bytes(streamid))] = self.persistent_connections.get(f"{ip}:{port}")

            relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.CONNECTED, K, "backward")
            connected_cell = TorCell(circid=int.from_bytes(circuid), cmd=TorCommands.RELAY, relay=relay_encrypted,
                            streamid=streamid_encrypted, digest=digest_encrypted, data=payload_encrypted)
            return connected_cell.to_bytes()
        else:
            self.logger.info("Connessione con server fallita: inoltro END")
            relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.END, K, "backward")
            end_cell = TorCell(circid=int.from_bytes(circuid), cmd=TorCommands.RELAY, relay=relay_encrypted,
                            streamid=streamid_encrypted, digest=digest_encrypted, data=payload_encrypted)
            return end_cell.to_bytes()

    def _forward_create(self, cell, payload_decrypted):
        decoded_payload = decode_payload(payload_decrypted, 3)
        g_x1_bytes_encrypted, port_bytes, ip_bytes = decoded_payload[0], decoded_payload[1], decoded_payload[2]
        
        port = int.from_bytes(port_bytes)
        ip_str = str(ipaddress.IPv4Address(ip_bytes))
        
        # Update routing table
        for entry in self.routing_table:
            if entry.get_circuit_id() == int.from_bytes(cell.circid):
                entry.set_dest_coords(ip_str, port)
                break
        
        create_cell = TorCell(circid=int.from_bytes(cell.circid) + 1, cmd=TorCommands.CREATE,
                             data=encode_payload([g_x1_bytes_encrypted]))
        
        response_data = self._forward_message("127.0.0.1", port, create_cell.to_bytes())
        return self._process_message(response_data, None, None) if response_data else None

    def _forward_relay(self, cell, relay_decrypted, streamid_decrypted, digest_decrypted, payload_decrypted):
        
        relay_cell = TorCell(circid=int.from_bytes(cell.circid) + 1, cmd=TorCommands.RELAY,
                           relay=relay_decrypted, streamid=streamid_decrypted,
                           digest=digest_decrypted, data=payload_decrypted)
        
        # Find destination port
        port = next(entry.get_dest_coords()[1] for entry in self.routing_table 
                   if entry.get_circuit_id() == int.from_bytes(cell.circid))
        
        response_data = self._forward_message("127.0.0.1", port, relay_cell.to_bytes())
        return self._process_message(response_data, None, None) if response_data else None

    def _forward_message(self, destination_ip: str, port: int, data):

        destination_key = f"{destination_ip}:{port}"

        if destination_key in self.persistent_connections:
            try:
                sock = self.persistent_connections[destination_key]
                sock.send(data)
                response_data = sock.recv(1000000)
                return response_data if response_data else None
            except Exception as e:
                self.logger.warning(f"Errore su connessione esistente a {destination_key}: {e}")
                # Rimuovi connessione non funzionante
                del self.persistent_connections[destination_key]

        # Crea nuova connessione se non esiste o quella esistente è fallita
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((destination_ip, port))
            
            # AGGIUNTA: salva la nuova connessione per riutilizzo

            self.persistent_connections[destination_key] = sock
            
            sock.send(data)
            response_data = sock.recv(1000000)
            return response_data if response_data else None
        except Exception as e:
            self.logger.error(f"Errore invio messaggio a {destination_ip}:{port}: {e}")
            return None
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
import time
from typing import Tuple

# Larghezza di banda rappresentata dai valori: 0: bassa, 1. media, 2:alta
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class Node:
    def __init__(self, node_id: str, node_type: str, ip_address: str, band_width: int, 
                 uptime: int, owner: str, port: int, compromise: bool):
        self.id = node_id
        self.ip = ip_address
        self.type = node_type
        self._priv, self.pub = gen_rsa_keypair()
        self.compromised = compromise
        self.band_width = band_width
        self.uptime = uptime
        self.owner = owner
        self.timing_data: List[float] = []
        
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.redirection = False

        self.routing_table: List[RoutingEntry] = []
        self.persistent_connections: Dict[str, socket.socket] = {}

        #serve per exit
        self.circuit_stream_socket_map: Dict[(int, int), socket.socket] = {}       
        self.logger = logging.getLogger(f"Nodo-{self.id}")

    def __str__(self):
        bandwidth_labels = {0: "bassa", 1: "media", 2: "alta", 3: "ottima"}
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
        
        self.persistent_connections[client_id] = client_socket

        try:
            while self.running:  # MODIFICA: loop per mantenere connessione aperta
                data = client_socket.recv(4096)
                
                if not data:
                    self.logger.info(f"Client {client_id} ha chiuso la connessione")
                    break
                    
                response_data = self._process_message(data, addr[0], addr[1], "forward")

                if response_data:

                    client_socket.sendall(response_data)

                    if(self.compromised):
                        self.compromised_log()
                
        except socket.timeout:
            self.logger.error(f"Timeout gestione client {client_id}")
        except Exception as e:
            self.logger.error(f"Errore gestione client {client_id}: {e}")
        finally:
            if client_id in self.persistent_connections:
                del self.persistent_connections[client_id]
            try:
                client_socket.close()
                self.logger.info(f"Connessione chiusa con {client_id}")
            except Exception as e:
                self.logger.debug(f"Errore chiusura connessione con {client_id}: {e}")

    def remove_circuit(self, routing_entry):
        affected_sockets = set()

        # Record sockets involved with entry
        src_ip, src_port = routing_entry.get_source_coords()
        dst_ip, dst_port = routing_entry.get_dest_coords()

        if src_ip and src_port:
            affected_sockets.add(f"{src_ip}:{src_port}")
        if dst_ip and dst_port:
            affected_sockets.add(f"{dst_ip}:{dst_port}")

        self.routing_table.remove(routing_entry)

        # Step 3: For each affected socket, check if it's still used elsewhere
        for sock_id in affected_sockets:
            still_used = any(
                sock_id in (
                    f"{e.get_source_coords()[0]}:{e.get_source_coords()[1]}",
                    f"{e.get_dest_coords()[0]}:{e.get_dest_coords()[1]}"
                )
                for e in self.routing_table
            )
            if not still_used and sock_id in self.persistent_connections:
                sock = self.persistent_connections.pop(sock_id)
                sock.shutdown(socket.SHUT_RDWR)
                self.logger.info(f"Closed and removed socket {sock_id}")

    def compromised_log(self):
        self.timing_data.append(time.time())

    def print_routing_entry_table(self,entry: RoutingEntry):
        rows = [
            ("Node type", entry.get_node_type()),
            ("Source IP", entry.get_source_coords()[0]),
            ("Source Port", entry.get_source_coords()[1]),
            ("Destination IP", entry.get_dest_coords()[0]),
            ("Destination Port", entry.get_dest_coords()[1]),
            ("Incoming Circuit ID", entry.get_in_circ_id()),
            ("Outgoing Circuit ID", entry.get_out_circ_id()),
            ("Created At", entry.get_creation_timestamp()),
        ]

        max_key_len = max(len(row[0]) for row in rows)
        print("=" * (max_key_len + 30))
        for key, val in rows:
            print(f"{key:<{max_key_len}} : {val}")
        print("=" * (max_key_len + 30))


    def generate_circuit_route(self):
         for entry in self.routing_table:
              self.print_routing_entry_table(entry)
         
        

    def _process_message(self, data, ip, port, direction):
        try:
            match self.band_width:
                case 2:
                    time.sleep(0)
                case 1:
                    time.sleep(0.3)
                case 0:
                    time.sleep(1)

            cell = TorCell.from_bytes(data)

            if int.from_bytes(cell.circid)!=0 and self.compromised:
                self.compromised_log()
                
            if cell.cmd == TorCommands.CREATE:
                return self._handle_create(cell, ip, port)
            elif cell.cmd == TorCommands.CREATED:
                return self._handle_created(cell, ip, port)
            elif cell.cmd == TorCommands.RELAY:
                return self._handle_relay(cell, ip, port, direction)
            elif cell.cmd == TorCommands.DESTROY:
                
                routing_entry = next(
                    (entry for entry in self.routing_table
                    if entry.get_in_circ_id() == int.from_bytes(cell.circid)
                    and entry.get_source_coords() == (ip, port)),
                    None  # default if no match is found
                )

                if self.type != "exit":
                    self.logger.info(f"Destroying circuit {routing_entry.get_in_circ_id()}-{routing_entry.get_out_circ_id()}...")

                    destroy_cell = TorCell(circid=routing_entry.get_out_circ_id(), cmd=TorCommands.DESTROY, data=b'null')
                    forward_sock = self.persistent_connections.get(f"127.0.0.1:{routing_entry.get_dest_coords()[1]}")

                    forward_sock.send(destroy_cell.to_bytes())
                    if(self.compromised):
                        self.compromised_log()

                    self.remove_circuit(routing_entry)

                    self.logger.info("Destroyed...")


                else:
                    self.logger.info(f"Destroying circuit {routing_entry.get_out_circ_id()}")

                    self.remove_circuit(routing_entry)
                    
                    # Collect keys to remove
                    keys_to_remove = [
                        key for key in self.circuit_stream_socket_map.keys()
                        if key[0] == routing_entry.get_in_circ_id()
                    ]

                    # Now safely remove them
                    for key in keys_to_remove:
                        self.circuit_stream_socket_map.pop(key)
                    self.logger.info("Destroyed...")


                
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
        return None

    def _handle_create(self, cell, ip, port):
        
        self.logger.info("Create ricevuta")

        g_x1_bytes_encrypted = decode_payload(cell.data, 1)[0]
        g_x1_bytes_decrypted = rsa_decrypt(self._priv, g_x1_bytes_encrypted)
        
        y1, g_y1, H_K, K = process_dh_handshake_response(g_x1_bytes_decrypted)

        if int.from_bytes(cell.circid)!=0 and self.compromised:
                self.compromised_log()

        new_routing_entry = RoutingEntry(ip, port, int.from_bytes(cell.circid), 
                                               self.allocate_circ_id_for_outgoing(int.from_bytes(cell.circid)+1), 
                                               K, time.time(),self.type)
        self.routing_table.append(new_routing_entry)

        created_cell = TorCell(circid=new_routing_entry.get_in_circ_id(), cmd=TorCommands.CREATED,
                              data=encode_payload([data_to_bytes(g_y1), H_K]))

        return created_cell.to_bytes()
    

    def _handle_created(self, cell,ip, port):
        
        decoded_payload = decode_payload(cell.data, 2)
        g_y1_bytes, H_K_TO_BE_FORWARDED = decoded_payload[0], decoded_payload[1]

        
        K, in_circ_id = next(
                        ((entry.get_session_key(), entry.get_in_circ_id()) for entry in self.routing_table
                        if entry.get_out_circ_id() == int.from_bytes(cell.circid)),
                        (None, None)  # default if no match is found
        )

        if int.from_bytes(cell.circid)!=0 and self.compromised:
                self.compromised_log()
        
        # Encrypt response
        relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.EXTENDED, K, "backward")
        streamid_encrypted, _ = aes_ctr_encrypt(data_to_bytes(0), K, "backward")
        digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(K), K, "backward")
        payload_encrypted, _ = aes_ctr_encrypt(encode_payload([g_y1_bytes, H_K_TO_BE_FORWARDED]), K, "backward")
        
        relay_cell = TorCell(circid=in_circ_id, cmd=TorCommands.RELAY, relay=relay_encrypted,
                           streamid=streamid_encrypted, digest=digest_encrypted, data=payload_encrypted)
        

        return relay_cell.to_bytes()

    def _handle_relay(self, cell, ip, port, direction):
        if direction == "backward":
            return self._handle_relay_backward(cell, ip, port)
        elif direction == "forward":
            return self._handle_relay_forward(cell, ip, port)
        else: return None

    def _handle_relay_backward(self, cell, ip, port):
        
        routing_entry = next(
                    (entry for entry in self.routing_table
                    if entry.get_out_circ_id() == int.from_bytes(cell.circid)
                    and entry.get_source_coords() == (ip, port)),
                    None  # default if no match is found
                )
        if int.from_bytes(cell.circid)!=0 and self.compromised:
                self.compromised_log()

        K = routing_entry.get_session_key()
        
        relay_encrypted, _ = aes_ctr_encrypt(cell.relay, K, "backward")
        streamid_encrypted, _ = aes_ctr_encrypt(cell.stream_id, K, "backward")
        digest_encrypted, _ = aes_ctr_encrypt(cell.digest, K, "backward")
        payload_encrypted, _ = aes_ctr_encrypt(cell.payload, K, "backward")
        
        relay_cell = TorCell(circid=routing_entry.get_in_circ_id(), cmd=TorCommands.RELAY,
                           relay=relay_encrypted, streamid=streamid_encrypted,
                           digest=digest_encrypted, data=payload_encrypted)
        return relay_cell.to_bytes()

    def _handle_relay_forward(self, cell, ip, port):

        # Find session key and decrypt
        routing_entry = next(
                    (entry for entry in self.routing_table
                    if entry.get_in_circ_id() == int.from_bytes(cell.circid)
                    and entry.get_source_coords() == (ip, port)),
                    None  # default if no match is found
                )
        
        if int.from_bytes(cell.circid)!=0 and self.compromised:
                self.compromised_log()
        
        K = routing_entry.get_session_key()

        relay_decrypted = aes_ctr_decrypt(cell.relay_command, K, "forward")
        streamid_decrypted = aes_ctr_decrypt(cell.streamid, K, "forward")
        digest_decrypted = aes_ctr_decrypt(cell.digest, K, "forward")
        payload_decrypted = aes_ctr_decrypt(cell.data, K, "forward")
        
        if digest_decrypted == calculate_digest(K):
            if relay_decrypted == RelayCommands.EXTEND:
                return self._forward_create(routing_entry, payload_decrypted, ip, port)
            elif relay_decrypted == RelayCommands.BEGIN:
                return self._connect_to_server(routing_entry, streamid_decrypted, payload_decrypted, ip, port)
            elif relay_decrypted == RelayCommands.DATA:

                if self.redirection:
                    destination_key = f"127.0.0.1:{self.attacker_server_port}"

                    if destination_key not in self.persistent_connections:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)  # avoid hanging forever
                            sock.connect(("127.0.0.1", self.attacker_server_port))
                            self.persistent_connections[destination_key] = sock
                            self.logger.info(f"[Exit {self.id}] Connected redirect socket to {destination_key}")
                        except Exception as e:
                            self.logger.error(f"[Exit {self.id}] Redirect connection failed: {e}")
                            return None

                    dst_socket = self.persistent_connections[destination_key]

                else:
                    dst_socket = self.circuit_stream_socket_map.get((routing_entry.get_in_circ_id(), int.from_bytes(streamid_decrypted)))
                    
                if self.compromised:
                        self.compromised_log()
                        
                dst_socket.send(payload_decrypted)  
                response_data = dst_socket.recv(1000000)
                if(self.compromised):
                        self.compromised_log()
                if response_data:
                    # Encrypt the response for backward transmission
                    relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.DATA, K, "backward")
                    streamid_encrypted, _ = aes_ctr_encrypt(streamid_decrypted, K, "backward")
                    digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(K), K, "backward")
                    payload_encrypted, _ = aes_ctr_encrypt(response_data, K, "backward")
                    
                    # Create RELAY DATA cell with server response
                    data_cell = TorCell(circid=routing_entry.get_in_circ_id(), cmd=TorCommands.RELAY, 
                                    relay=relay_encrypted, streamid=streamid_encrypted,
                                    digest=digest_encrypted, data=payload_encrypted)
                    return data_cell.to_bytes()
                else:
                    return None
        else:
            return self._forward_relay(routing_entry, relay_decrypted, streamid_decrypted, 
                                      digest_decrypted, payload_decrypted, ip, port)

    def _connect_to_server(self, routing_entry, streamid, payload, ip, port):

        decoded_payload = decode_payload(payload, 2)

        ip_bytes, port_bytes = decoded_payload[0], decoded_payload[1]

        port = int.from_bytes(port_bytes)
        
        ip_str = str(ipaddress.IPv4Address(ip_bytes))

        response = self._forward_message("127.0.0.1", port, encode_payload([data_to_bytes("test")]))


        K = routing_entry.get_session_key()
                
        streamid_encrypted, _ = aes_ctr_encrypt(streamid, K, "backward")
        digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(K), K, "backward")
        payload_encrypted, _ = aes_ctr_encrypt(response, K, "backward")

        
        if response:

            routing_entry.set_dest_coords("127.0.0.1", port)
            self.circuit_stream_socket_map[(routing_entry.get_in_circ_id(), int.from_bytes(streamid))] = self.persistent_connections.get(f"{ip}:{port}")

            relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.CONNECTED, K, "backward")
            connected_cell = TorCell(circid=routing_entry.get_in_circ_id(), cmd=TorCommands.RELAY, relay=relay_encrypted,
                            streamid=streamid_encrypted, digest=digest_encrypted, data=payload_encrypted)
            return connected_cell.to_bytes()
        else:
            self.logger.info("Connessione con server fallita: inoltro END")
            relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.END, K, "backward")
            end_cell = TorCell(circid=routing_entry.get_in_circ_id(), cmd=TorCommands.RELAY, relay=relay_encrypted,
                            streamid=streamid_encrypted, digest=digest_encrypted, data=payload_encrypted)
            return end_cell.to_bytes()

    def _forward_create(self, routing_entry, payload_decrypted, src_ip, src_port):
        decoded_payload = decode_payload(payload_decrypted, 3)
        g_x1_bytes_encrypted, port_bytes, ip_bytes = decoded_payload[0], decoded_payload[1], decoded_payload[2]
        
        port = int.from_bytes(port_bytes)
        ip_str = str(ipaddress.IPv4Address(ip_bytes))

        routing_entry.set_dest_coords("127.0.0.1", port)
        
        create_cell = TorCell(circid=routing_entry.get_out_circ_id(), cmd=TorCommands.CREATE,
                             data=encode_payload([g_x1_bytes_encrypted]))
        response_data = self._forward_message("127.0.0.1", port, create_cell.to_bytes())
        return self._process_message(response_data, src_ip, src_port, "forward") if response_data else None

    def _forward_relay(self, routing_entry, relay_decrypted, streamid_decrypted, digest_decrypted, payload_decrypted, src_ip, src_port):
        
        relay_cell = TorCell(circid=routing_entry.get_out_circ_id(), cmd=TorCommands.RELAY,
                           relay=relay_decrypted, streamid=streamid_decrypted,
                           digest=digest_decrypted, data=payload_decrypted)
        


        response_data = self._forward_message("127.0.0.1", routing_entry.get_dest_coords()[1], relay_cell.to_bytes())
        return self._process_message(response_data, src_ip, src_port, "backward") if response_data else None

    def _forward_message(self, destination_ip: str, port: int, data):

        destination_key = f"{destination_ip}:{port}"

        if destination_key in self.persistent_connections:
            try:
                sock = self.persistent_connections[destination_key]
                if(self.compromised):
                        self.compromised_log()
                sock.send(data)
                response_data = sock.recv(1000000)
                if(self.compromised):
                        self.compromised_log()
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
            if(self.compromised):
                       self.compromised_log()
            sock.send(data)
            response_data = sock.recv(1000000)
            if(self.compromised):
                        self.compromised_log()
            return response_data if response_data else None
        except Exception as e:
            self.logger.error(f"Errore invio messaggio a {destination_ip}:{port}: {e}")
            return None
        
    def allocate_circ_id_for_outgoing(self, out_conn):
        used = {entry.get_out_circ_id() for entry in self.routing_table}

        if out_conn not in used:
            return out_conn
        else:
            for candidate in range(out_conn, 65536):
                if candidate not in used:
                    return candidate
            raise RuntimeError("No free circ_id")
        
    def _set_exit_redirection(self, redirection, attacker_server_ip, attacker_server_port):
        if self.type == 'exit' and self.compromised:
            self.redirection = redirection
            self.attacker_server_ip = attacker_server_ip
            self.attacker_server_port = attacker_server_port
    
    def _flood_circuit(self, ip, port, n, pub_key, delay=None):
        if self.compromised:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", port))    
            try:
                while True:
                    x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(pub_key)
                    create_cell = TorCell(circid=(0).to_bytes(2, 'big'),
                                        cmd=TorCommands.CREATE,
                                        data=encode_payload([g_x1_bytes_encrypted]))
                    sock.sendall(create_cell.to_bytes())
                    if delay:
                        time.sleep(delay)
            finally:
                sock.close()
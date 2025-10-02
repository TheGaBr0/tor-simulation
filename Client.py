from Cryptograpy_utils import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Directory_Server import DirectoryServer
from Node import Node
from typing import List, Optional, Dict, Tuple
from collections import defaultdict

import random
import logging
import socket
from TorMessage import *
import json
import base64
import pickle
import threading
import ipaddress
from RoutingEntry import RoutingEntry

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class Client:
    def __init__(self, id: str, ip: str, port: int, listen_port: int, choice_algorithm='default'):
        self.id = id
        self.ip = ip
        self.choice_algorithm = choice_algorithm
        self.running =False

        self.len_of_circuit = None

        self.guard_chosen = None
        self.relays_chosen = None
        self.exit_chosen = None
   
        self.nodes = []
        self.handshake_enstablished = False
        
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.listen_port = listen_port
        
        self.client_socket: Optional[socket.socket] = None
        self.persistent_connections: Dict[str, socket.socket] = {}
        self.server_stream_circuit_map: Dict[str, (int, int)] = {} #Dict[socket.socket, (int, int)] = {} -> nella realtà per applicazioni

        self.circuit_relays_map: Dict[int, List[int]] = defaultdict(list)
        
        self.logger = logging.getLogger(f"Client-{self.id}")

    def determine_route(self):
        
        if not self._send_request_to_directory("127.0.0.1", 9000, self._craft_request_directory_server()):
            self.logger.info("Ricezione nodi fallita, abort.")
            return
            
        self.logger.info(f"Nodi ricevuti, determinando il percorso di {self.len_of_circuit} nodi...")

        circuit = self.build_circuit()

        self.guard_chosen = circuit[0]
        self.relays_chosen = circuit[1:-1]  # All middle nodes
        self.exit_chosen = circuit[-1]

        for node in circuit:
            node.start()
        
        relay_info = '\n - '.join([str(relay) for relay in self.relays_chosen])
        self.logger.info(f"Percorso scelto: \n - {self.guard_chosen}\n - {relay_info}\n - {self.exit_chosen}")


    def establish_circuit(self, circuit_id):
        # Handshake with guard
        if not self._handshake_guard(circuit_id):
            self.logger.warning("Errore nell'handshake con guard")
            return False
        
        # Handshake with relay
        if not self._handshake_relay(circuit_id):
            self.logger.warning("Errore nell'handshake con relay")
            return False
            
        # Handshake with exit
        if not self._handshake_exit(circuit_id):
            self.logger.warning("Errore nell'handshake con exit")
            return False

        return True
    

    def _handshake_guard(self, circuit_id):
        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(self.guard_chosen.pub)
        self.g_x1, self.x1 = g_x1, x1
        
        create_cell = TorCell(circid=circuit_id, cmd=TorCommands.CREATE, data=encode_payload([g_x1_bytes_encrypted]))
        
        success = self._send_request("127.0.0.1", self.guard_chosen.port, create_cell.to_bytes())
        self.logger.info("Handshake con guard " + ("completato" if success else "fallito"))
        return success

    def _handshake_relay(self, circuit_id):

        for i, node in enumerate(self.relays_chosen):
            x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(node.pub)
            self.g_x1, self.x1 = g_x1, x1
            
            payload = encode_payload([g_x1_bytes_encrypted, data_to_bytes(node.port), data_to_bytes(node.ip)])
            
            relay = RelayCommands.EXTEND
            streamid = data_to_bytes(0)
            digest = calculate_digest(self.circuit_relays_map[circuit_id][-1])
            payload = payload

            for K in self.circuit_relays_map[circuit_id]:
                relay, _ = aes_ctr_encrypt(relay, K, "forward")
                streamid, _ = aes_ctr_encrypt(streamid, K, "forward")
                digest, _ = aes_ctr_encrypt(digest, K, "forward")
                payload, _ = aes_ctr_encrypt(payload, K, "forward")
            
            relay_cell = TorCell(circid=circuit_id, cmd=TorCommands.RELAY, relay=relay, 
                            streamid=streamid, digest=digest, data=payload)
            
            success = self._send_request("127.0.0.1", self.guard_chosen.port, relay_cell.to_bytes())

            if not success:
                return success
            else:
                self.logger.info(f"Handshake con relay {i+1} {'completato' if success else 'fallito'}")
        
        return success

    def _handshake_exit(self, circuit_id):
        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(self.exit_chosen.pub)
        self.g_x1, self.x1 = g_x1, x1
        
        payload = encode_payload([g_x1_bytes_encrypted, data_to_bytes(self.exit_chosen.port), data_to_bytes(self.exit_chosen.ip)])
        
        relay = RelayCommands.EXTEND
        streamid = data_to_bytes(0)
        digest = calculate_digest(self.circuit_relays_map[circuit_id][-1])
        payload = payload

        for K in self.circuit_relays_map[circuit_id]:
            relay, _ = aes_ctr_encrypt(relay, K, "forward")
            streamid, _ = aes_ctr_encrypt(streamid, K, "forward")
            digest, _ = aes_ctr_encrypt(digest, K, "forward")
            payload, _ = aes_ctr_encrypt(payload, K, "forward")
        
        relay_cell = TorCell(circid=circuit_id, cmd=TorCommands.RELAY, relay=relay, 
                            streamid=streamid, digest=digest, data=payload)
        
        success = self._send_request("127.0.0.1", self.guard_chosen.port, relay_cell.to_bytes())
        self.logger.info("Handshake con exit " + ("completato" if success else "fallito"))

        return success

    def connect_to_tor_network(self, circuit_id, len_of_circuit = 3):
        
        self.len_of_circuit = len_of_circuit

        self.determine_route()
        
        self.handshake_enstablished = self.establish_circuit(circuit_id)
        return self.handshake_enstablished

    def send_message_to_tor_network(self, server_ip: str, server_port: int, payload: str, circuit_id: int):

        success = self.enstablish_connection_with_server(server_ip, server_port, circuit_id)
        
        if(success):
            self.send_message_to_server(server_ip, server_port, payload)

    def enstablish_connection_with_server(self, server_ip: str, server_port: int, circuit_id: int) -> bool:
        
        payload = encode_payload([data_to_bytes(server_ip), data_to_bytes(server_port)])

        used_stream_ids = {v[1] for v in self.server_stream_circuit_map.values()}
        random_stream_id = self._random_stream_id(used_stream_ids)

        self.server_stream_circuit_map[f"{server_ip}:{server_port}"] = (circuit_id ,random_stream_id) 

        relay = RelayCommands.BEGIN
        streamid = data_to_bytes(data_to_bytes(random_stream_id))
        digest = calculate_digest(self.circuit_relays_map[circuit_id][-1])
        payload = payload

        for K in self.circuit_relays_map[circuit_id]:
            relay, _ = aes_ctr_encrypt(relay, K, "forward")
            streamid, _ = aes_ctr_encrypt(streamid, K, "forward")
            digest, _ = aes_ctr_encrypt(digest, K, "forward")
            payload, _ = aes_ctr_encrypt(payload, K, "forward")
        
        relay_cell = TorCell(circid=circuit_id, cmd=TorCommands.RELAY, relay=relay, 
                        streamid=streamid, digest=digest, data=payload)
        
        success = self._send_request("127.0.0.1", self.guard_chosen.port, relay_cell.to_bytes())
        

        return success
    
    def send_message_to_server(self, server_ip: str, server_port: int, payload: str) -> bytes:
        payload = encode_payload([data_to_bytes(payload)])

        circid, streamid = self.server_stream_circuit_map.get(f"{server_ip}:{server_port}")

        relay = RelayCommands.DATA
        streamid = data_to_bytes(streamid)
        digest = calculate_digest(self.circuit_relays_map[circid][-1])
        payload = payload

        for K in self.circuit_relays_map[circid]:
            relay, _ = aes_ctr_encrypt(relay, K, "forward")
            streamid, _ = aes_ctr_encrypt(streamid, K, "forward")
            digest, _ = aes_ctr_encrypt(digest, K, "forward")
            payload, _ = aes_ctr_encrypt(payload, K, "forward")
        
        relay_cell = TorCell(circid=circid, cmd=TorCommands.RELAY, relay=relay, 
                            streamid=streamid, digest=digest, data=payload)
        
        
        success = self._send_request("127.0.0.1", self.guard_chosen.port, relay_cell.to_bytes())


    def _craft_request_directory_server(self):
        return json.dumps({"id": self.id, "cmd": "RETRIEVE"}).encode('utf-8')

    def _send_request(self, server_ip: str, server_port: int, payload: bytes) -> bool:
        destination_key = f"{server_ip}:{server_port}"
        
        # AGGIUNTA: riutilizza connessione esistente se disponibile
        if destination_key in self.persistent_connections:
            try:
                sock = self.persistent_connections[destination_key]
                sock.sendall(payload)
                response_data = sock.recv(1000000)
                
                if response_data:
                    return self._process_message(response_data)
                else:
                    self.logger.warning("No response received from existing connection")
                    # Rimuovi connessione non funzionante
                    del self.persistent_connections[destination_key]
            except Exception as e:
                self.logger.warning(f"Errore su connessione esistente a {destination_key}: {e}")
                # Rimuovi connessione non funzionante
                if destination_key in self.persistent_connections:
                    del self.persistent_connections[destination_key]
        
        # Crea nuova connessione se non esiste o quella esistente è fallita
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20.0)
            sock.connect((server_ip, server_port))
            
            # AGGIUNTA: salva la nuova connessione per riutilizzo
            self.persistent_connections[destination_key] = sock
            
            sock.sendall(payload)
            response_data = sock.recv(1000000)
            
            if response_data:
                return self._process_message(response_data)
            else:
                self.logger.warning("No response received from server")
                
        except socket.timeout:
            self.logger.error("Request timeout")
        except Exception as e:
            self.logger.error(f"Error in _send_request: {e}")
        return False
    
    def _send_request_to_directory(self, server_ip: str, server_port: int, payload: bytes) -> bool:
        try:
            # Create new socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20.0)
            sock.connect((server_ip, server_port))
            
            
            # Send payload
            sock.sendall(payload)
            
            # Receive all data in chunks
            response_data = b''
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response_data += chunk
            
            # Close socket
            sock.close()
            
            if response_data:
                return self._process_message(response_data)
            else:
                self.logger.warning("No response received from server")
                return False
                
        except socket.timeout:
            self.logger.error("Request timeout")
            return False
        except Exception as e:
            self.logger.error(f"Error in _send_request: {e}")
            return False
    
    def close_connections(self):
        """Chiude tutte le connessioni persistenti"""
        for conn in self.persistent_connections.values():
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except:
                pass
        self.persistent_connections.clear()
        self.logger.info("Tutte le connessioni persistenti chiuse")

    def _process_message(self, data: bytes) -> bool:
        try:
            try:
                cell = TorCell.from_bytes(data)
            except ValueError:
                # RETRIEVED response
                packet = pickle.loads(data)
                self.nodes = packet.get("nodes", [])
                return True

            if cell.cmd == TorCommands.CREATED:
                decoded_payload = decode_payload(cell.data, 2)
                g_y1_bytes, H_K1_toCheck = decoded_payload[0], decoded_payload[1]
                
                g_y1 = int.from_bytes(g_y1_bytes, 'big')
                self.circuit_relays_map[int.from_bytes(cell.circid)].append(pow(g_y1, self.x1, DH_PRIME))
                H_K1 = process_dh_handshake_final(g_y1_bytes, self.x1)

                return H_K1_toCheck == H_K1
            
            if cell.cmd == TorCommands.RELAY:
                relay, streamid, digest, data = cell.relay_command, cell.streamid, cell.digest, cell.data
                

                keys_list = [k for k in self.circuit_relays_map[int.from_bytes(cell.circid)]]

                for K in keys_list:  

                    relay = aes_ctr_decrypt(relay, K, "backward")
                    streamid = aes_ctr_decrypt(streamid, K, "backward")
                    digest = aes_ctr_decrypt(digest, K, "backward")
                    data = aes_ctr_decrypt(data, K, "backward")
                    
                    if not self._is_handshake_completed(int.from_bytes(cell.circid)):
                        
                        try:
                            
                            decoded_payload = decode_payload(data, 2)
                            g_y1_bytes, H_K2_toCheck = decoded_payload[0], decoded_payload[1]

                            g_y1 = int.from_bytes(g_y1_bytes, 'big')
                            H_K = process_dh_handshake_final(g_y1_bytes, self.x1)
                            
                            if H_K == H_K2_toCheck:
                                self.circuit_relays_map[int.from_bytes(cell.circid)].append(pow(g_y1, self.x1, DH_PRIME))
                                return True
                        except Exception:
                            continue
                
                match relay:
                    case RelayCommands.CONNECTED:
                        return True
                    case RelayCommands.END:
                        return False

                    case RelayCommands.DATA:
                        self.logger.info(decode_payload(data,1)[0].decode('utf-8'))
                        self.logger.info(f"streamid: {int.from_bytes(streamid)} id: {int.from_bytes(cell.circid)}")
                        return True

                        
        except Exception as e:
            self.logger.error(f"Errore processando messaggio: {e}")
        return False
    
    def _is_handshake_completed(self, circuit_id):
        keys_list = [k for k in self.circuit_relays_map[circuit_id]]
        return len(keys_list) == self.len_of_circuit
    
    def _random_stream_id(self, used_ids):
        """
        Generate a random Tor stream ID (valid range: 1 to 2^31 - 1).
        """
        while True:
            stream_id = random.randint(1, 2**16 - 1)
            if stream_id not in used_ids:
                return stream_id

    
    def _choose_from_top3(self, nodes, node_type):
        filtered = [n for n in self.nodes if n.type == node_type]
        sorted_nodes = sorted(filtered, key=lambda n: n.band_width, reverse=True)
        best_three = sorted_nodes[:3]
        
        if self.choice_algorithm != 'greedy':
            random.shuffle(best_three)
        return best_three[0]
    
    def _select_best_node(self, nodes: list[Node]) -> Node:
        """
        Select the best node from a list based on bandwidth and choice algorithm
        """
        sorted_nodes = sorted(nodes, key=lambda n: n.band_width, reverse=True)
        best_three = sorted_nodes[:3]
        
        if self.choice_algorithm != 'greedy':
            random.shuffle(best_three)
        
        return best_three[0]
    
    def _get_16_subnet(self, ip: str) -> str:
        """
        Extract the /16 subnet from an IP address
        """
        return '.'.join(ip.split('.')[:2])
    
    def build_circuit(self) -> list[Node]:
        """
        Build a circuit with self.len_of_circuit nodes:
        - 1 guard (first node)
        - self.len_of_circuit-2 relays (middle nodes)
        - 1 exit (last node)
        
        """
        if self.len_of_circuit < 3:
            raise ValueError("Circuit length must be at least 3 nodes")
        
        circuit = []
        used_owners = set()
        used_subnets = set()
        
        # Step 1: Choose guard

        if not self.guard_chosen:
            guard = self._choose_from_top3(self.nodes, "guard")
        else:
            guard = self.guard_chosen

        circuit.append(guard)
        used_owners.add(guard.owner)
        used_subnets.add(self._get_16_subnet(guard.ip))
        
        # Step 2: Choose relays (len_of_circuit - 2 nodes)
        num_relays = self.len_of_circuit - 2
        
        for i in range(num_relays):
            # Filter available relays
            available_relays = [
                n for n in self.nodes 
                if n.type == "relay" 
                and n.owner not in used_owners
                and self._get_16_subnet(n.ip) not in used_subnets
            ]
            
            if not available_relays:
                raise ValueError(f"No available relays for position {i+2} in circuit")
            
            # Select best relay
            relay = self._select_best_node(available_relays)
            circuit.append(relay)
            used_owners.add(relay.owner)
            used_subnets.add(self._get_16_subnet(relay.ip))
        
        # Step 3: Choose exit
        available_exits = [
            n for n in self.nodes 
            if n.type == "exit"
            and n.owner not in used_owners
            and self._get_16_subnet(n.ip) not in used_subnets
        ]
        
        if not available_exits:
            raise ValueError("No available exits for circuit")
        
        exit_node = self._select_best_node(available_exits)
        circuit.append(exit_node)
        
        return circuit
from Cryptograpy_utils import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Directory_Server import DirectoryServer
from Node import Node
from typing import List, Optional, Dict, Tuple

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
        self.running = False

        self.guard_chosen = None
        self.relay_chosen = None
        self.exit_chosen = None
        self.K1 = self.K2 = self.K3 = None
        self.nodes = []
        self.handshake_enstablished = False
        
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.listen_port = listen_port
        self.client_socket: Optional[socket.socket] = None
        self.persistent_connections: Dict[str, socket.socket] = {}
        self.server_stream_circuit_map: Dict[str, (int, int)] = {} #Dict[socket.socket, (int, int)] = {} -> nella realtà per applicazioni

        self.circuit_relays_map: Dict[int, List[Tuple[str, int]]] = {}
        
        self.logger = logging.getLogger(f"Client-{self.id}")

    def determine_route(self):
        self.logger.info("Richiedendo i nodi al directory server")
        
        if not self._send_request("127.0.0.1", 9000, self._craft_request_directory_server()):
            self.logger.info("Ricezione nodi fallita, abort.")
            return
            
        self.logger.info("Nodi ricevuti, determinando il percorso...")
        self.guard_chosen = self._choose_guard()
        self.relay_chosen = self._choose_relay()
        self.exit_chosen = self._choose_exit()
        
        self.logger.info(f"Percorso scelto: \n - {self.guard_chosen}\n - {self.relay_chosen}\n - {self.exit_chosen}")

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
        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(self.relay_chosen.pub)
        self.g_x1, self.x1 = g_x1, x1
        
        payload = encode_payload([g_x1_bytes_encrypted, data_to_bytes(self.relay_chosen.port), data_to_bytes(self.relay_chosen.ip)])
        
        # Encrypt with K1
        relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.EXTEND, self.K1, "forward")
        streamid_encrypted, _ = aes_ctr_encrypt(data_to_bytes(0), self.K1, "forward")
        digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(self.K1), self.K1, "forward")
        payload_encrypted, _ = aes_ctr_encrypt(payload, self.K1, "forward")
        
        relay_cell = TorCell(circid=circuit_id, cmd=TorCommands.RELAY, relay=relay_encrypted, 
                           streamid=streamid_encrypted, digest=digest_encrypted, data=payload_encrypted)
        
        success = self._send_request("127.0.0.1", self.guard_chosen.port, relay_cell.to_bytes())
        self.logger.info("Handshake con relay " + ("completato" if success else "fallito"))
        return success

    def _handshake_exit(self, circuit_id):
        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(self.exit_chosen.pub)
        self.g_x1, self.x1 = g_x1, x1
        
        payload = encode_payload([g_x1_bytes_encrypted, data_to_bytes(self.exit_chosen.port), data_to_bytes(self.exit_chosen.ip)])
        
        # Double encryption with K2 then K1
        relay_encrypted_K2, _ = aes_ctr_encrypt(RelayCommands.EXTEND, self.K2, "forward")
        streamid_encrypted_K2, _ = aes_ctr_encrypt(data_to_bytes(0), self.K2, "forward")
        digest_encrypted_K2, _ = aes_ctr_encrypt(calculate_digest(self.K2), self.K2, "forward")
        payload_encrypted_K2, _ = aes_ctr_encrypt(payload, self.K2, "forward")
        
        relay_encrypted_K1, _ = aes_ctr_encrypt(relay_encrypted_K2, self.K1, "forward")
        streamid_encrypted_K1, _ = aes_ctr_encrypt(streamid_encrypted_K2, self.K1, "forward")
        digest_encrypted_K1, _ = aes_ctr_encrypt(digest_encrypted_K2, self.K1, "forward")
        payload_encrypted_K1, _ = aes_ctr_encrypt(payload_encrypted_K2, self.K1, "forward")
        
        relay_cell = TorCell(circid=circuit_id, cmd=TorCommands.RELAY, relay=relay_encrypted_K1,
                           streamid=streamid_encrypted_K1, digest=digest_encrypted_K1, data=payload_encrypted_K1)
        
        success = self._send_request("127.0.0.1", self.guard_chosen.port, relay_cell.to_bytes())
        self.logger.info("Handshake con exit " + ("completato" if success else "fallito"))

        return success

    def connect_to_tor_network(self, circuit_id):
        self.determine_route()
        for node in [self.guard_chosen, self.relay_chosen, self.exit_chosen]:
            node.start()

        self.handshake_enstablished = self.establish_circuit(circuit_id)

        if self.handshake_enstablished:
            self.circuit_relays_map[circuit_id] = [(f"{self.guard_chosen.ip}:{self.guard_chosen.port}", self.K1),
                                               (f"{self.relay_chosen.ip}:{self.relay_chosen.port}", self.K2),
                                                (f"{self.exit_chosen.ip}:{self.exit_chosen.port}", self.K3)]

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

        relay_encrypted_K3, _ = aes_ctr_encrypt(RelayCommands.BEGIN, self.K3, "forward")
        streamid_encrypted_K3, _ = aes_ctr_encrypt(data_to_bytes(random_stream_id), self.K3, "forward")
        digest_encrypted_K3, _ = aes_ctr_encrypt(calculate_digest(self.K3), self.K3, "forward")
        payload_encrypted_K3, _ = aes_ctr_encrypt(payload, self.K3, "forward")

        relay_encrypted_K2, _ = aes_ctr_encrypt(relay_encrypted_K3, self.K2, "forward")
        streamid_encrypted_K2, _ = aes_ctr_encrypt(streamid_encrypted_K3, self.K2, "forward")
        digest_encrypted_K2, _ = aes_ctr_encrypt(digest_encrypted_K3, self.K2, "forward")
        payload_encrypted_K2, _ = aes_ctr_encrypt(payload_encrypted_K3, self.K2, "forward")
        
        relay_encrypted_K1, _ = aes_ctr_encrypt(relay_encrypted_K2, self.K1, "forward")
        streamid_encrypted_K1, _ = aes_ctr_encrypt(streamid_encrypted_K2, self.K1, "forward")
        digest_encrypted_K1, _ = aes_ctr_encrypt(digest_encrypted_K2, self.K1, "forward")
        payload_encrypted_K1, _ = aes_ctr_encrypt(payload_encrypted_K2, self.K1, "forward")
        
        relay_cell = TorCell(circid=circuit_id, cmd=TorCommands.RELAY, relay=relay_encrypted_K1,
                           streamid=streamid_encrypted_K1, digest=digest_encrypted_K1, data=payload_encrypted_K1)
        
        success = self._send_request("127.0.0.1", self.guard_chosen.port, relay_cell.to_bytes())
        
        if success:
            self.logger.info("Connessione al server stabilita con successo")

        return success
    
    def send_message_to_server(self, server_ip: str, server_port: int, payload: str) -> bytes:
        payload = encode_payload([data_to_bytes(payload)])

        self.logger.info(self.server_stream_circuit_map)
        circid, streamid = self.server_stream_circuit_map.get(f"{server_ip}:{server_port}")

        relay_encrypted_K3, _ = aes_ctr_encrypt(RelayCommands.DATA, self.K3, "forward")
        streamid_encrypted_K3, _ = aes_ctr_encrypt(data_to_bytes(streamid), self.K3, "forward")
        digest_encrypted_K3, _ = aes_ctr_encrypt(calculate_digest(self.K3), self.K3, "forward")
        payload_encrypted_K3, _ = aes_ctr_encrypt(payload, self.K3, "forward")

        relay_encrypted_K2, _ = aes_ctr_encrypt(relay_encrypted_K3, self.K2, "forward")
        streamid_encrypted_K2, _ = aes_ctr_encrypt(streamid_encrypted_K3, self.K2, "forward")
        digest_encrypted_K2, _ = aes_ctr_encrypt(digest_encrypted_K3, self.K2, "forward")
        payload_encrypted_K2, _ = aes_ctr_encrypt(payload_encrypted_K3, self.K2, "forward")
        
        relay_encrypted_K1, _ = aes_ctr_encrypt(relay_encrypted_K2, self.K1, "forward")
        streamid_encrypted_K1, _ = aes_ctr_encrypt(streamid_encrypted_K2, self.K1, "forward")
        digest_encrypted_K1, _ = aes_ctr_encrypt(digest_encrypted_K2, self.K1, "forward")
        payload_encrypted_K1, _ = aes_ctr_encrypt(payload_encrypted_K2, self.K1, "forward")
        
        relay_cell = TorCell(circid=circid, cmd=TorCommands.RELAY, relay=relay_encrypted_K1,
                           streamid=streamid_encrypted_K1, digest=digest_encrypted_K1, data=payload_encrypted_K1)
        
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
            sock.settimeout(10.0)
            sock.connect((server_ip, server_port))
            
            # AGGIUNTA: salva la nuova connessione per riutilizzo
            self.persistent_connections[destination_key] = sock
            self.logger.info(f"Connected to {server_ip}:{server_port}")
            
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
                self.logger.info("Risposta RETRIEVED ricevuta")
                packet = pickle.loads(data)
                self.nodes = packet.get("nodes", [])
                return True

            if cell.cmd == TorCommands.CREATED:
                self.logger.info("Risposta CREATED ricevuta")
                decoded_payload = decode_payload(cell.data, 2)
                g_y1_bytes, H_K1_toCheck = decoded_payload[0], decoded_payload[1]
                
                g_y1 = int.from_bytes(g_y1_bytes, 'big')
                self.K1 = pow(g_y1, self.x1, DH_PRIME)
                H_K1 = process_dh_handshake_final(g_y1_bytes, self.x1)
                
                print(f"Confronto chiavi:\n{H_K1.hex()}\n{H_K1_toCheck.hex()}\nUguaglianza: {H_K1_toCheck == H_K1}")
                return H_K1_toCheck == H_K1
            
            if cell.cmd == TorCommands.RELAY:
                self.logger.info("Cella RELAY ricevuta")
                relay, streamid, digest, data = cell.relay_command, cell.streamid, cell.digest, cell.data
                
                if not self.handshake_enstablished:
                    keys_list = [self.K1, self.K2, self.K3]
                else:
                    keys_list = [k for _, k in self.circuit_relays_map[int.from_bytes(cell.circid)]]

                for i, K in enumerate(keys_list):
                    relay = aes_ctr_decrypt(relay, K, "backward")
                    streamid = aes_ctr_decrypt(streamid, K, "backward")
                    digest = aes_ctr_decrypt(digest, K, "backward")
                    data = aes_ctr_decrypt(data, K, "backward")
                    
                    if not self.handshake_enstablished:
                        try:
                            decoded_payload = decode_payload(data, 2)
                            g_y1_bytes, H_K2_toCheck = decoded_payload[0], decoded_payload[1]
                            g_y1 = int.from_bytes(g_y1_bytes, 'big')
                            H_K = process_dh_handshake_final(g_y1_bytes, self.x1)
                            
                            if H_K == H_K2_toCheck:
                                self.logger.info(f"Confronto chiavi avvenuto con successo:\n{H_K.hex()}\n{H_K2_toCheck.hex()}")
                                if i == 0:
                                    self.K2 = pow(g_y1, self.x1, DH_PRIME)
                                else:
                                    self.K3 = pow(g_y1, self.x1, DH_PRIME)
                                return True
                        except Exception:
                            continue
                
                match relay:
                    case RelayCommands.CONNECTED:
                        self.logger.info("Cella RELAY CONNECTED identificata")
                        return True
                    case RelayCommands.END:
                        self.logger.info("Cella RELAY END identificata")
                        return False

                    case RelayCommands.DATA:
                        self.logger.info("Cella RELAY DATA identificata")
                        self.logger.info(decode_payload(data,1)[0])
                        self.logger.info(f"streamid: {int.from_bytes(streamid)} id: {int.from_bytes(cell.circid)}")
                        return True

                        
        except Exception as e:
            self.logger.error(f"Errore processando messaggio: {e}")
        return False
    
    def _random_stream_id(self, used_ids):
        """
        Generate a random Tor stream ID (valid range: 1 to 2^31 - 1).
        """
        while True:
            stream_id = random.randint(1, 2**16 - 1)
            if stream_id not in used_ids:
                return stream_id
    
    def _same_16_subnet(self, ip1: str, ip2: str) -> bool:
        octets1, octets2 = ip1.split('.'), ip2.split('.')
        return octets1[0] == octets2[0] and octets1[1] == octets2[1]
    
    def _choose_from_top3(self, nodes, node_type):
        filtered = [n for n in self.nodes if n.type == node_type]
        sorted_nodes = sorted(filtered, key=lambda n: n.band_width, reverse=True)
        best_three = sorted_nodes[:3]
        
        if self.choice_algorithm != 'greedy':
            random.shuffle(best_three)
        return best_three[0]
    
    def _choose_guard(self) -> Node:
        if self.guard_chosen:
            return self.guard_chosen
        else:
            return self._choose_from_top3(self.nodes, "guard")
            
    def _choose_relay(self) -> Node:
        if not self.guard_chosen:
            raise ValueError("Nessun guard scelto prima di scegliere un relay.")
        
        relays = [n for n in self.nodes if n.type == "relay" and n.owner != self.guard_chosen.owner 
                 and not self._same_16_subnet(n.ip, self.guard_chosen.ip)]
        
        sorted_relays = sorted(relays, key=lambda n: n.band_width, reverse=True)
        best_three = sorted_relays[:3]
        
        if self.choice_algorithm != 'greedy':
            random.shuffle(best_three)
        return best_three[0]
    
    def _choose_exit(self) -> Node:
        if not self.guard_chosen or not self.relay_chosen:
            raise ValueError("Nessun guard/exit scelto prima di scegliere un exit.")
        
        exits = [n for n in self.nodes if n.type == "exit" 
                and n.owner not in [self.guard_chosen.owner, self.relay_chosen.owner]
                and not any(self._same_16_subnet(n.ip, node.ip) for node in [self.guard_chosen, self.relay_chosen])]
        
        sorted_exits = sorted(exits, key=lambda n: n.band_width, reverse=True)
        best_three = sorted_exits[:3]
        
        if self.choice_algorithm != 'greedy':
            random.shuffle(best_three)
        return best_three[0]
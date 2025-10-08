from Cryptograpy_utils import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Directory_Server import DirectoryServer
from Node import Node
from typing import List, Optional, Dict, Tuple
from collections import defaultdict

import time
import random
import logging
import socket
from TorMessage import *
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] (%(name)s) %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

class Client:
    def __init__(self, id: str, ip: str, port: int, listen_port: int, nodes, choice_algorithm='default'):
        self.id = id
        self.ip = ip
        self.choice_algorithm = choice_algorithm
        self.running =False

        self.len_of_circuit = None
   
        self.nodes = nodes
        self.handshake_enstablished = False
        
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.listen_port = listen_port
        
        self.client_socket: Optional[socket.socket] = None
        self.persistent_connections: Dict[str, socket.socket] = {}
        self.server_stream_circuit_map: Dict[str, List[(int, int)]] = defaultdict(list) #Dict[socket.socket, (int, int)] = {} -> nella realtà per applicazioni

        self.circuits = defaultdict(list)
        self.circuit_relays_map: Dict[int, List[int]] = defaultdict(list)
        
        self.logger = logging.getLogger(f"Client-{self.id}")

    def get_guard(self, circuit_id):
        return self.circuits.get(circuit_id)[0]
    
    def get_relays(self, circuit_id):
        return self.circuits.get(circuit_id)[1:-1]
    
    def get_exit(self, circuit_id):
        return self.circuits.get(circuit_id)[-1]

    def determine_route(self, circuit_id):
        self.logger.info(f"Selecting a {self.len_of_circuit}-hop circuit route...")
        circuit = self.build_circuit()

        self.circuits[circuit_id].extend(circuit)
        
        route_str = "\n    → ".join([f"{n.type.upper()}:{n.id} [{n.ip}:{n.port}] ({n.owner})" for n in circuit])
        self.logger.info(f"Circuit #{circuit_id} route established:\n    → {route_str}")


    def establish_circuit(self, circuit_id):
        self.logger.info(f"Establishing circuit #{circuit_id} handshake sequence...")
        
        if not self._handshake_guard(circuit_id):
            self.logger.warning("Guard handshake failed — aborting circuit setup.")
            return False
        if not self._handshake_relay(circuit_id):
            self.logger.warning("Relay handshake failed — aborting circuit setup.")
            return False
        if not self._handshake_exit(circuit_id):
            self.logger.warning("Exit handshake failed — aborting circuit setup.")
            return False
        
        self.logger.info(f"Circuit #{circuit_id} established successfully with {self.len_of_circuit} hops.")
        return True

    

    def _handshake_guard(self, circuit_id):
        self.logger.info(f"Performing Diffie–Hellman handshake with guard node {self.get_guard(circuit_id).ip}:{self.get_guard(circuit_id).port}...")
        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(self.get_guard(circuit_id).pub)
        self.g_x1, self.x1 = g_x1, x1
        create_cell = TorCell(circid=circuit_id, cmd=TorCommands.CREATE, data=encode_payload([g_x1_bytes_encrypted]))
        
        success = self._send_request("127.0.0.1", self.get_guard(circuit_id).port, create_cell.to_bytes())

        if success:
            self.logger.info("Handshake with guard succedeed")
        return success

    def _handshake_relay(self, circuit_id):

        for i, node in enumerate(self.get_relays(circuit_id)):
            self.logger.info(f"Extending circuit through relay {i+1} ({node.ip}:{node.port})...")
            x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(node.pub)
            self.g_x1, self.x1 = g_x1, x1
            
            payload = encode_payload([g_x1_bytes_encrypted, data_to_bytes(node.port), data_to_bytes(node.ip)], is_relay=True)
            
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
            
            success = self._send_request("127.0.0.1", self.get_guard(circuit_id).port, relay_cell.to_bytes())

            if not success:
                return success
            else:
                self.logger.info(f"Relay {i+1} extension succeeded.")
        
        return success

    def _handshake_exit(self, circuit_id):
        self.logger.info(f"Extending circuit to exit node {self.get_exit(circuit_id).ip}:{self.get_exit(circuit_id).port}...")
        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(self.get_exit(circuit_id).pub)
        self.g_x1, self.x1 = g_x1, x1
        
        payload = encode_payload([g_x1_bytes_encrypted, data_to_bytes(self.get_exit(circuit_id).port), data_to_bytes(self.get_exit(circuit_id).ip)], is_relay=True)
        
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
        
        success = self._send_request("127.0.0.1", self.get_guard(circuit_id).port, relay_cell.to_bytes())
        
        if success:
            self.logger.info("Exit node handshake completed.")

        return success

    def connect_to_tor_network(self, circuit_id, len_of_circuit=3):
        if circuit_id in self.circuits:
            self.logger.warning(f"Circuit ID {circuit_id} already exists. Skipping new connection.")
            return
        self.len_of_circuit = len_of_circuit
        self.logger.info(f"Connecting to Tor network with {len_of_circuit}-hop circuit...")
        
        self.determine_route(circuit_id)
        self.handshake_enstablished = self.establish_circuit(circuit_id)
        
        if self.handshake_enstablished:
            self.logger.info(f"Connection to Tor network established via circuit #{circuit_id}.")
        else:
            self.logger.error(f"Failed to connect to Tor network (circuit #{circuit_id}).")
        return self.handshake_enstablished

    
    def destroy_circuit(self, circuit_id):

        self.logger.info(f"Tearing down circuit #{circuit_id}...")

        destroy_cell = TorCell(circid=circuit_id, cmd=TorCommands.DESTROY, data=b'null')
        sock = self.persistent_connections.get(f"127.0.0.1:{self.get_guard(circuit_id).port}")

        if not sock:
            self.logger.warning(f"No connection found for circuit {circuit_id}")
            return False

        # Send destroy message
        sock.send(destroy_cell.to_bytes())

        # Wait for destroy to propagate through the circuit
        time.sleep(2)

        # Remove tuples from each list where tuple[0] == circuit_id
        for lst in self.server_stream_circuit_map.values():
            # Filter in-place: keep only tuples whose first element != circuit_id
            lst[:] = [tup for tup in lst if tup[0] != circuit_id]

        self.circuit_relays_map.pop(circuit_id, None)

        # Check if any other circuits are using the same guard connection
        other_circuits_using_guard = [
            cid for cid in self.circuit_relays_map.keys() 
            if cid != circuit_id
        ]

        # Only close the connection if no other circuits are using it
        if not other_circuits_using_guard:
            self.persistent_connections.pop(f"127.0.0.1:{self.get_guard(circuit_id).port}", None)
            sock.close()
            print(f"Closed connection to guard (no other circuits using it)")
        else:
            print(f"Keeping connection to guard (other circuits: {other_circuits_using_guard})")

        self.circuits.pop(circuit_id)

        self.logger.info(f"Circuit #{circuit_id} destroyed successfully.")
        return True

    def send_message_to_tor_network(self, server_ip: str, server_port: int, payload: str, circuit_id: int):

        if circuit_id not in self.circuits:
            self.logger.warning(f"Circuit #{circuit_id} not found. Message aborted.")
            return

        value_list = self.server_stream_circuit_map.get(f"{server_ip}:{server_port}")
        if not value_list or all(tup[0] != circuit_id for tup in value_list):            
            success = self.enstablish_connection_with_server(server_ip, server_port, circuit_id)
            if(success):
                self.logger.info(f"Sending application data through circuit #{circuit_id} to {server_ip}:{server_port}...")
            else:
                self.logger.info(f"Couldn't enstablish connection through circuit #{circuit_id} to {server_ip}:{server_port}...")
        else:
            success = True

        if(success):
            self.send_message_to_server(server_ip, server_port, payload, circuit_id)

    def enstablish_connection_with_server(self, server_ip: str, server_port: int, circuit_id: int) -> bool:
        
        payload = encode_payload([data_to_bytes(server_ip), data_to_bytes(server_port)], is_relay=True)

        used_stream_ids = {item[1] for lst in self.server_stream_circuit_map.values() for item in lst}
        random_stream_id = self._random_stream_id(used_stream_ids)

        self.server_stream_circuit_map[f"{server_ip}:{server_port}"].append((circuit_id, random_stream_id))

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
        
        success = self._send_request("127.0.0.1", self.get_guard(circuit_id).port, relay_cell.to_bytes())
        

        return success
    
    def send_message_to_server(self, server_ip: str, server_port: int, payload: str, circuit_id: int) -> bytes:
        payload = encode_payload([data_to_bytes(payload)], is_relay=True)

        key = f"{server_ip}:{server_port}"
        streamid = None

        tuple_list = self.server_stream_circuit_map.get(key, [])

        for tup in tuple_list:
            if tup[0] == circuit_id:
                streamid = tup[1]
                break

        if streamid is None:
            # circuit_id not found
            raise ValueError(f"Circuit ID {circuit_id} not found for {key}")

        relay = RelayCommands.DATA
        streamid = data_to_bytes(streamid)
        digest = calculate_digest(self.circuit_relays_map[circuit_id][-1])
        payload = payload

        for K in self.circuit_relays_map[circuit_id]:
            relay, _ = aes_ctr_encrypt(relay, K, "forward")
            streamid, _ = aes_ctr_encrypt(streamid, K, "forward")
            digest, _ = aes_ctr_encrypt(digest, K, "forward")
            payload, _ = aes_ctr_encrypt(payload, K, "forward")
        
        relay_cell = TorCell(circid=circuit_id, cmd=TorCommands.RELAY, relay=relay, 
                            streamid=streamid, digest=digest, data=payload)
        
        
        success = self._send_request("127.0.0.1", self.get_guard(circuit_id).port, relay_cell.to_bytes())

    def _send_request(self, server_ip: str, server_port: int, payload: bytes) -> bool:
        destination_key = f"{server_ip}:{server_port}"
        self.logger.debug(f"Sending Tor cell to {destination_key}...")

        if destination_key in self.persistent_connections:
            try:
                sock = self.persistent_connections[destination_key]
                sock.sendall(payload)
                response_data = sock.recv(512)
                
                if response_data:
                    self.logger.debug(f"Received response from {destination_key}")
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
            sock.connect((server_ip, server_port))
            
            # AGGIUNTA: salva la nuova connessione per riutilizzo
            self.persistent_connections[destination_key] = sock
            
            sock.sendall(payload)
            response_data = sock.recv(512)
            
            if response_data:
                self.logger.debug(f"Received response from {destination_key}")
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

            cell = TorCell.from_bytes(data)
            
            circ_id = int.from_bytes(cell.circid)
            
            if cell.cmd == TorCommands.CREATED:
                self.logger.info(f"[Circuit {circ_id}] Received CREATED cell.")

                decoded_payload = decode_payload(cell.data, 2)
                g_y1_bytes, H_K1_toCheck = decoded_payload[0], decoded_payload[1]
                
                g_y1 = int.from_bytes(g_y1_bytes, 'big')
                self.circuit_relays_map[int.from_bytes(cell.circid)].append(pow(g_y1, self.x1, DH_PRIME))
                H_K1 = process_dh_handshake_final(g_y1_bytes, self.x1)

                #print(f"Confronto chiavi:\n{H_K1.hex()}\n{H_K1_toCheck.hex()}\nUguaglianza: {H_K1_toCheck == H_K1}")
                return H_K1_toCheck == H_K1
            
            if cell.cmd == TorCommands.RELAY:
                relay, streamid, digest, data = cell.relay_command, cell.streamid, cell.digest, cell.data
                self.logger.debug(f"[Circuit {circ_id}] Received RELAY cell. Attempting layered decryption...")


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
                                #self.logger.info(f"Confronto chiavi avvenuto con successo:\n{H_K.hex()}\n{H_K2_toCheck.hex()}")
                                self.circuit_relays_map[int.from_bytes(cell.circid)].append(pow(g_y1, self.x1, DH_PRIME))
                                return True
                        except Exception:
                            continue
                
                match relay:
                    case RelayCommands.CONNECTED:
                        self.logger.info(f"[Circuit {circ_id}] Received CONNECTED cell.")
                        return True
                    case RelayCommands.END:
                        self.logger.warning(f"[Circuit {circ_id}] Received CONNECTED cell. Stream closed.")
                        return False
                    case RelayCommands.DATA:
                        message = decode_payload(data,1)[0].decode('utf-8')
                        self.logger.info(f"[Circuit {circ_id}] Received DATA cell, message: {message}, stream id:  {int.from_bytes(streamid)}")
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



    def _select_best_node(self, nodes: list[Node], 
                     bandwidth_weight: float = 0.9,
                     uptime_weight: float = 0.1,
                     top_n: int = 3) -> Node:
        """
        Select the best node from a list based on weighted bandwidth and uptime.
        
        Args:
            nodes: List of nodes to select from
            bandwidth_weight: Weight for bandwidth (default: 0.7)
            uptime_weight: Weight for uptime (default: 0.3)
            top_n: Number of top candidates to randomly choose from (default: 5)
        
        Returns:
            Randomly selected node from top N candidates
        
        Raises:+
            ValueError: If nodes list is empty
        """
        if not nodes:
            raise ValueError("Cannot select from empty node list")
        
        # Calculate weighted scores
        scored_nodes = [
            (node, node.band_width * bandwidth_weight + node.uptime * uptime_weight) 
            for node in nodes
        ]
        
        # Sort by score and take top N
        sorted_nodes = sorted(scored_nodes, key=lambda x: x[1], reverse=True)
        top_scored = sorted_nodes[:top_n]
                
        top_candidates = [node for node, _ in top_scored]

        for node in top_candidates:
            print(node.type+","+node.id+";")

        selected = random.choice(top_candidates)
        
        return selected


    def _get_16_subnet(self, ip: str) -> str:
        """
        Extract the /16 subnet from an IP address.
        
        Args:
            ip: IP address string (e.g., '192.168.1.1')
        
        Returns:
            /16 subnet (e.g., '192.168')
        """
        return '.'.join(ip.split('.')[:2])


    def _filter_available_nodes(self, node_type: str, 
                                exclude_owners: set, 
                                exclude_subnets: set) -> list[Node]:
        """
        Filter nodes by type and exclusion criteria.
        
        Args:
            node_type: Type of node to filter ('guard', 'relay', 'exit')
            exclude_owners: Set of owners to exclude
            exclude_subnets: Set of /16 subnets to exclude
        
        Returns:
            List of available nodes matching criteria
        """
        return [
            node for node in self.nodes 
            if node.type == node_type 
            and node.owner not in exclude_owners
            and self._get_16_subnet(node.ip) not in exclude_subnets
        ]


    def build_circuit(self) -> list[Node]:
        """
        Build a circuit with diverse nodes to enhance anonymity.
        
        The circuit consists of:
        - 1 guard node (entry)
        - N relay nodes (middle, where N = len_of_circuit - 2)
        - 1 exit node
        
        Diversity constraints:
        - No two nodes share the same owner
        - No two nodes share the same /16 subnet
        
        Returns:
            List of nodes forming the circuit
        
        Raises:
            ValueError: If circuit length < 3 or insufficient diverse nodes available
        """
        if self.len_of_circuit < 3:
            raise ValueError("Circuit length must be at least 3 nodes")
        
        circuit = []
        used_owners = set()
        used_subnets = set()
        
        # Step 1: Select guard node
        # Reuse existing guard if circuits already exist
        if self.circuits:
            first_key = next(iter(self.circuits))
            guard = self.get_guard(first_key)
        else:
            available_guards = self._filter_available_nodes("guard", used_owners, used_subnets)
            if not available_guards:
                raise ValueError("No available guard nodes")
            guard = self._select_best_node(available_guards)
        
        circuit.append(guard)
        used_owners.add(guard.owner)
        used_subnets.add(self._get_16_subnet(guard.ip))
        
        # Step 2: Select relay nodes
        num_relays = self.len_of_circuit - 2
        
        for i in range(num_relays):
            available_relays = self._filter_available_nodes("relay", used_owners, used_subnets)
            
            if not available_relays:
                raise ValueError(
                    f"No available relays for position {i + 2} in circuit. "
                    f"Used owners: {len(used_owners)}, Used subnets: {len(used_subnets)}"
                )
            
            relay = self._select_best_node(available_relays)
            circuit.append(relay)
            used_owners.add(relay.owner)
            used_subnets.add(self._get_16_subnet(relay.ip))
        
        # Step 3: Select exit node
        available_exits = self._filter_available_nodes("exit", used_owners, used_subnets)
        
        if not available_exits:
            raise ValueError(
                f"No available exits for circuit. "
                f"Used owners: {len(used_owners)}, Used subnets: {len(used_subnets)}"
            )
        
        exit_node = self._select_best_node(available_exits)
        circuit.append(exit_node)
        
        return circuit
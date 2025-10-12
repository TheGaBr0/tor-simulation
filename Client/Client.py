from Utils.Cryptograpy_utils import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Server.Directory_Server import DirectoryServer
from TorNetwork.Node import Node
from typing import List, Optional, Dict, Tuple
from collections import defaultdict
import time
import random
import logging
import socket
from TorNetwork.TorMessage import *

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] (%(name)s) %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

class Client:
    """
    Tor client implementation that manages circuit creation, message routing,
    and communication with the Tor network.
    """
    
    def __init__(self, id: str, ip: str, port: int, oracle, nodes):
        self.id = id
        self.ip = ip
        self.running = False
        self.oracle = oracle
        self.len_of_circuit = None
   
        self.nodes = nodes
        self.handshake_enstablished = False
        
        self.bind_ip = "127.0.0.1"
        self.port = port
        
        self.client_socket: Optional[socket.socket] = None
        self.persistent_connections: Dict[str, socket.socket] = {}
        
        # Maps server address to list of (circuit_id, stream_id) tuples
        self.server_stream_circuit_map: Dict[str, List[Tuple[int, int]]] = defaultdict(list)

        # Maps circuit_id to list of Node objects forming the circuit
        self.circuits = defaultdict(list)
        
        # Maps circuit_id to list of shared secrets (keys) for each hop
        self.circuit_relays_map: Dict[int, List[int]] = defaultdict(list)
        
        self.logger = logging.getLogger(f"Client-{self.id}")

        self.oracle.add_symb_ip(self.ip, self.port)

    def get_guard(self, circuit_id):
        """Get the guard (entry) node for a specific circuit."""
        return self.circuits.get(circuit_id)[0]
    
    def get_relays(self, circuit_id):
        """Get all middle relay nodes for a specific circuit."""
        return self.circuits.get(circuit_id)[1:-1]
    
    def get_exit(self, circuit_id):
        """Get the exit node for a specific circuit."""
        return self.circuits.get(circuit_id)[-1]

    def determine_route(self, circuit_id):
        """Select and store the node path for a new circuit."""
        self.logger.info(f"Selecting a {self.len_of_circuit}-hop circuit route...")
        circuit = self.build_circuit()

        self.circuits[circuit_id].extend(circuit)
        
        route_str = "\n    → ".join([
            f"{n.type.upper()}:{n.id} [{n.ip}:{n.port}] ({n.owner})" 
            for n in circuit
        ])
        self.logger.info(f"Circuit #{circuit_id} route established:\n    → {route_str}")

    def establish_circuit(self, circuit_id):
        """
        Perform the full handshake sequence to establish a circuit.
        This includes handshakes with guard, relay(s), and exit nodes.
        """
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
        """Perform Diffie-Hellman handshake with the guard node."""
        guard = self.get_guard(circuit_id)
        self.logger.info(f"Performing Diffie–Hellman handshake with guard node {guard.ip}:{guard.port}...")
        
        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(guard.pub)
        self.g_x1, self.x1 = g_x1, x1
        
        create_cell = TorCell(
            circid=circuit_id, 
            cmd=TorCommands.CREATE, 
            data=encode_payload([g_x1_bytes_encrypted])
        )
        
        success = self._send_request("127.0.0.1", guard.port, create_cell.to_bytes())

        if success:
            self.logger.info("Handshake with guard succeeded")
        return success

    def _handshake_relay(self, circuit_id):
        """Extend the circuit through all middle relay nodes."""
        for i, node in enumerate(self.get_relays(circuit_id)):
            self.logger.info(f"Extending circuit through relay {i+1} ({node.ip}:{node.port})...")
            
            x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(node.pub)
            self.g_x1, self.x1 = g_x1, x1
            
            payload = encode_payload([
                g_x1_bytes_encrypted, 
                data_to_bytes(node.port), 
                data_to_bytes(node.ip)
            ], is_relay=True)
            
            # Prepare relay cell with encryption layers
            relay = RelayCommands.EXTEND
            streamid = data_to_bytes(0)
            digest = calculate_digest(self.circuit_relays_map[circuit_id][-1])

            # Apply layered encryption for all existing hops
            for K in self.circuit_relays_map[circuit_id]:
                relay, _ = aes_ctr_encrypt(relay, K, "forward")
                streamid, _ = aes_ctr_encrypt(streamid, K, "forward")
                digest, _ = aes_ctr_encrypt(digest, K, "forward")
                payload, _ = aes_ctr_encrypt(payload, K, "forward")
            
            relay_cell = TorCell(
                circid=circuit_id, 
                cmd=TorCommands.RELAY, 
                relay=relay, 
                streamid=streamid, 
                digest=digest, 
                data=payload
            )
            
            success = self._send_request("127.0.0.1", self.get_guard(circuit_id).port, relay_cell.to_bytes())

            if not success:
                return False
            else:
                self.logger.info(f"Relay {i+1} extension succeeded.")
        
        return True

    def _handshake_exit(self, circuit_id):
        """Extend the circuit to the final exit node."""
        exit_node = self.get_exit(circuit_id)
        self.logger.info(f"Extending circuit to exit node {exit_node.ip}:{exit_node.port}...")
        
        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(exit_node.pub)
        self.g_x1, self.x1 = g_x1, x1
        
        payload = encode_payload([
            g_x1_bytes_encrypted, 
            data_to_bytes(exit_node.port), 
            data_to_bytes(exit_node.ip)
        ], is_relay=True)
        
        relay = RelayCommands.EXTEND
        streamid = data_to_bytes(0)
        digest = calculate_digest(self.circuit_relays_map[circuit_id][-1])

        # Apply layered encryption through all hops
        for K in self.circuit_relays_map[circuit_id]:
            relay, _ = aes_ctr_encrypt(relay, K, "forward")
            streamid, _ = aes_ctr_encrypt(streamid, K, "forward")
            digest, _ = aes_ctr_encrypt(digest, K, "forward")
            payload, _ = aes_ctr_encrypt(payload, K, "forward")
        
        relay_cell = TorCell(
            circid=circuit_id, 
            cmd=TorCommands.RELAY, 
            relay=relay, 
            streamid=streamid, 
            digest=digest, 
            data=payload
        )
        
        success = self._send_request("127.0.0.1", self.get_guard(circuit_id).port, relay_cell.to_bytes())
        
        if success:
            self.logger.info("Exit node handshake completed.")

        return success

    def connect_to_tor_network(self, circuit_id, len_of_circuit=3):
        """
        Establish a complete connection to the Tor network with a new circuit.
        Returns True if successful, False otherwise.
        """
        if circuit_id in self.circuits:
            self.logger.warning(f"Circuit ID {circuit_id} already exists. Skipping new connection.")
            return False
            
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
        """
        Tear down a circuit by sending a DESTROY cell and cleaning up all
        associated state and connections.
        """
        self.logger.info(f"Tearing down circuit #{circuit_id}...")

        destroy_cell = TorCell(
            circid=circuit_id, 
            cmd=TorCommands.DESTROY, 
            data=encode_payload([data_to_bytes("null")])
        )
        sock = self.persistent_connections.get(f"127.0.0.1:{self.get_guard(circuit_id).port}")

        if not sock:
            self.logger.warning(f"No connection found for circuit {circuit_id}")
            return False

        # Send destroy message through the circuit
        sock.send(destroy_cell.to_bytes())
        
        # Wait for destroy to propagate
        time.sleep(2)

        # Remove all stream associations for this circuit
        for lst in self.server_stream_circuit_map.values():
            lst[:] = [tup for tup in lst if tup[0] != circuit_id]

        self.circuit_relays_map.pop(circuit_id, None)

        # Check if other circuits are using the same guard connection
        other_circuits_using_guard = [
            cid for cid in self.circuit_relays_map.keys() 
            if cid != circuit_id
        ]

        # Only close connection if no other circuits depend on it
        if not other_circuits_using_guard:
            _, local_port = sock.getsockname()
            self.oracle.del_symb_ip(local_port)
            self.persistent_connections.pop(f"127.0.0.1:{self.get_guard(circuit_id).port}", None)
            sock.close()
            print(f"Closed connection to guard (no other circuits using it)")
        else:
            print(f"Keeping connection to guard (other circuits: {other_circuits_using_guard})")

        self.circuits.pop(circuit_id)

        self.logger.info(f"Circuit #{circuit_id} destroyed successfully.")
        return True

    def send_message_to_tor_network(self, server_ip: str, server_port: int, payload: str, circuit_id: int):
        """
        Send application data to a destination server through a specific circuit.
        If no stream exists for this server on this circuit, establish one first.
        """
        if circuit_id not in self.circuits:
            self.logger.warning(f"Circuit #{circuit_id} not found. Message aborted.")
            return

        value_list = self.server_stream_circuit_map.get(f"{server_ip}:{server_port}")
        
        # Check if a stream already exists for this circuit and server
        if not value_list or all(tup[0] != circuit_id for tup in value_list):            
            success = self.enstablish_connection_with_server(server_ip, server_port, circuit_id)
            if success:
                self.logger.info(f"Sending application data through circuit #{circuit_id} to {server_ip}:{server_port}...")
            else:
                self.logger.info(f"Couldn't establish connection through circuit #{circuit_id} to {server_ip}:{server_port}...")
        else:
            success = True

        if success:
            self.send_message_to_server(server_ip, server_port, payload, circuit_id)

    def enstablish_connection_with_server(self, server_ip: str, server_port: int, circuit_id: int) -> bool:
        """
        Establish a new stream to a destination server by sending a BEGIN cell
        through the circuit. Assigns a unique stream ID for this connection.
        """
        payload = encode_payload([
            data_to_bytes(server_ip), 
            data_to_bytes(server_port)
        ], is_relay=True)

        # Generate unique stream ID
        used_stream_ids = {item[1] for lst in self.server_stream_circuit_map.values() for item in lst}
        random_stream_id = self._random_stream_id(used_stream_ids)

        self.server_stream_circuit_map[f"{server_ip}:{server_port}"].append((circuit_id, random_stream_id))

        relay = RelayCommands.BEGIN
        streamid = data_to_bytes(random_stream_id)
        digest = calculate_digest(self.circuit_relays_map[circuit_id][-1])

        # Apply layered encryption
        for K in self.circuit_relays_map[circuit_id]:
            relay, _ = aes_ctr_encrypt(relay, K, "forward")
            streamid, _ = aes_ctr_encrypt(streamid, K, "forward")
            digest, _ = aes_ctr_encrypt(digest, K, "forward")
            payload, _ = aes_ctr_encrypt(payload, K, "forward")
        
        relay_cell = TorCell(
            circid=circuit_id, 
            cmd=TorCommands.RELAY, 
            relay=relay, 
            streamid=streamid, 
            digest=digest, 
            data=payload
        )
        
        success = self._send_request("127.0.0.1", self.get_guard(circuit_id).port, relay_cell.to_bytes())
        return success
    
    def send_message_to_server(self, server_ip: str, server_port: int, payload: str, circuit_id: int):
        """
        Send application data through an established stream using a DATA cell.
        """
        payload = encode_payload([data_to_bytes(payload)], is_relay=True)

        key = f"{server_ip}:{server_port}"
        streamid = None

        # Find the stream ID associated with this circuit
        tuple_list = self.server_stream_circuit_map.get(key, [])
        for tup in tuple_list:
            if tup[0] == circuit_id:
                streamid = tup[1]
                break

        if streamid is None:
            raise ValueError(f"Circuit ID {circuit_id} not found for {key}")

        relay = RelayCommands.DATA
        streamid = data_to_bytes(streamid)
        digest = calculate_digest(self.circuit_relays_map[circuit_id][-1])

        # Apply layered encryption
        for K in self.circuit_relays_map[circuit_id]:
            relay, _ = aes_ctr_encrypt(relay, K, "forward")
            streamid, _ = aes_ctr_encrypt(streamid, K, "forward")
            digest, _ = aes_ctr_encrypt(digest, K, "forward")
            payload, _ = aes_ctr_encrypt(payload, K, "forward")
        
        relay_cell = TorCell(
            circid=circuit_id, 
            cmd=TorCommands.RELAY, 
            relay=relay, 
            streamid=streamid, 
            digest=digest, 
            data=payload
        )
        
        self._send_request("127.0.0.1", self.get_guard(circuit_id).port, relay_cell.to_bytes())

    def _send_request(self, server_ip: str, server_port: int, payload: bytes) -> bool:
        """
        Send a Tor cell to a destination, reusing persistent connections when possible.
        Creates new connections if none exist or if the existing one has failed.
        """
        destination_key = f"{server_ip}:{server_port}"
        self.logger.debug(f"Sending Tor cell to {destination_key}...")

        # Try to reuse existing connection
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
                    del self.persistent_connections[destination_key]
            except Exception as e:
                self.logger.warning(f"Error on existing connection to {destination_key}: {e}")
                if destination_key in self.persistent_connections:
                    del self.persistent_connections[destination_key]
        
        # Create new connection if needed
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_ip, server_port))

            _, local_port = sock.getsockname()
            self.oracle.add_symb_ip(self.ip, local_port)
        
            # Save connection for reuse
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
        """Close all persistent connections gracefully."""
        for conn in self.persistent_connections.values():
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except:
                pass
        self.persistent_connections.clear()
        self.logger.info("All persistent connections closed")

    def _process_message(self, data: bytes) -> bool:
        """
        Process incoming Tor cells by decrypting layers and handling different
        cell types (CREATED, RELAY, etc.).
        """
        try:
            cell = TorCell.from_bytes(data)
            circ_id = int.from_bytes(cell.circid)
            
            if cell.cmd == TorCommands.CREATED:
                self.logger.info(f"[Circuit {circ_id}] Received CREATED cell.")

                decoded_payload = decode_payload(cell.data, 2)
                g_y1_bytes, H_K1_toCheck = decoded_payload[0], decoded_payload[1]
                
                g_y1 = int.from_bytes(g_y1_bytes, 'big')
                self.circuit_relays_map[circ_id].append(pow(g_y1, self.x1, DH_PRIME))
                H_K1 = process_dh_handshake_final(g_y1_bytes, self.x1)

                return H_K1_toCheck == H_K1
            
            if cell.cmd == TorCommands.RELAY:
                relay, streamid, digest, data = cell.relay_command, cell.streamid, cell.digest, cell.data
                self.logger.debug(f"[Circuit {circ_id}] Received RELAY cell. Attempting layered decryption...")

                keys_list = list(self.circuit_relays_map[circ_id])

                # Decrypt layers from outermost to innermost
                for K in keys_list:  
                    relay = aes_ctr_decrypt(relay, K, "backward")
                    streamid = aes_ctr_decrypt(streamid, K, "backward")
                    digest = aes_ctr_decrypt(digest, K, "backward")
                    data = aes_ctr_decrypt(data, K, "backward")
                    
                    # Check if this is part of handshake process
                    if not self._is_handshake_completed(circ_id):
                        try:
                            decoded_payload = decode_payload(data, 2)
                            g_y1_bytes, H_K2_toCheck = decoded_payload[0], decoded_payload[1]

                            g_y1 = int.from_bytes(g_y1_bytes, 'big')
                            H_K = process_dh_handshake_final(g_y1_bytes, self.x1)
                            
                            if H_K == H_K2_toCheck:
                                self.circuit_relays_map[circ_id].append(pow(g_y1, self.x1, DH_PRIME))
                                return True
                        except Exception:
                            continue
                
                # Handle different relay commands
                match relay:
                    case RelayCommands.CONNECTED:
                        self.logger.info(f"[Circuit {circ_id}] Received CONNECTED cell.")
                        return True
                    case RelayCommands.END:
                        self.logger.warning(f"[Circuit {circ_id}] Received END cell. Stream closed.")
                        return False
                    case RelayCommands.DATA:
                        message = decode_payload(data, 1)[0].decode('utf-8')
                        self.logger.info(f"[Circuit {circ_id}] Received DATA cell, message: {message}, stream id: {int.from_bytes(streamid)}")
                        return True
                        
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
        return False
    
    def _is_handshake_completed(self, circuit_id):
        """Check if all handshakes for the circuit are complete."""
        keys_list = list(self.circuit_relays_map[circuit_id])
        return len(keys_list) == self.len_of_circuit
    
    def _random_stream_id(self, used_ids):
        """Generate a unique random stream ID in the valid range [1, 2^16-1]."""
        while True:
            stream_id = random.randint(1, 2**16 - 1)
            if stream_id not in used_ids:
                return stream_id

    def _calculate_node_weights(self, nodes: List[Node], 
                                bandwidth_weight: float = 0.95,
                                uptime_weight: float = 0.05) -> Dict[str, float]:
        """
        Calculate weighted probabilities for node selection based on bandwidth and uptime.
        Higher bandwidth nodes are strongly preferred while maintaining some uptime consideration.
        """
        if not nodes:
            raise ValueError("Cannot select from empty node list")
        
        # Calculate weighted scores for each node
        node_scores = {
            node.id: (node.band_width * bandwidth_weight + node.uptime * uptime_weight)
            for node in nodes
        }
        
        total_score = sum(node_scores.values())

        # Fallback to uniform distribution if all scores are zero
        if total_score == 0:
            prob = 1.0 / len(nodes)
            return {node.id: prob for node in nodes}
        
        # Normalize scores to probabilities
        return {
            node_id: score / total_score 
            for node_id, score in node_scores.items()
        }
    
    def _get_node(self, nodes: List[Node], 
                  bandwidth_weight: float = 0.999,
                  uptime_weight: float = 0.001) -> Node:
        """
        Select a node from the list using weighted random selection.
        Heavily favors high-bandwidth nodes.
        """
        probabilities = self._calculate_node_weights(
            nodes, bandwidth_weight, uptime_weight
        )

        return random.choices(
            nodes,
            weights=[probabilities[n.id] for n in nodes],
            k=1
        )[0]

    def _get_16_subnet(self, ip: str) -> str:
        """
        Extract the /16 subnet from an IP address for diversity checks.
        """
        return '.'.join(ip.split('.')[:2])

    def _filter_available_nodes(self, node_type: str, 
                                exclude_owners: set, 
                                exclude_subnets: set) -> List[Node]:
        """
        Filter nodes by type while enforcing diversity constraints.
        """
        return [
            node for node in self.nodes 
            if node.type == node_type 
            and node.owner not in exclude_owners
            and self._get_16_subnet(node.ip) not in exclude_subnets
        ]

    def build_circuit(self) -> List[Node]:
        """
        Build a Tor circuit with diverse nodes to enhance anonymity.
        
        The circuit structure:
        - 1 guard node (entry point)
        - N relay nodes (middle hops, where N = len_of_circuit - 2)
        - 1 exit node
        
        Diversity constraints enforced:
        - No two nodes share the same owner (prevents single entity control)
        - No two nodes share the same /16 subnet (prevents network-level correlation)
        """
        if self.len_of_circuit < 3:
            raise ValueError("Circuit length must be at least 3 nodes")
        
        circuit = []
        used_owners = set()
        used_subnets = set()
        
        # Step 1: Select guard node (reuse existing guard if circuits already exist)
        if self.circuits:
            first_key = next(iter(self.circuits))
            guard = self.get_guard(first_key)
        else:
            available_guards = self._filter_available_nodes("guard", used_owners, used_subnets)
            if not available_guards:
                raise ValueError("No available guard nodes")
            guard = self._get_node(available_guards)
        
        circuit.append(guard)
        used_owners.add(guard.owner)
        used_subnets.add(self._get_16_subnet(guard.ip))
        
        # Step 2: Select middle relay nodes
        num_relays = self.len_of_circuit - 2
        
        for i in range(num_relays):
            available_relays = self._filter_available_nodes("relay", used_owners, used_subnets)
            
            if not available_relays:
                raise ValueError(
                    f"No available relays for position {i + 2} in circuit. "
                    f"Used owners: {len(used_owners)}, Used subnets: {len(used_subnets)}"
                )
            
            relay = self._get_node(available_relays)
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
        
        exit_node = self._get_node(available_exits)
        circuit.append(exit_node)
        
        return circuit
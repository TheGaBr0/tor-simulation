from Utils.Cryptograpy_utils import *
import threading
import socket
import logging
from typing import Optional, Dict, List, Tuple
import ipaddress
from TorNetwork.TorMessage import *
from TorNetwork.RoutingEntry import RoutingEntry
import time

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] (%(name)s) %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

class Node:
    """
    Represents a Tor network node (guard, middle, or exit).
    Handles circuit creation, relay forwarding, and persistent connections.
    """
    
    def __init__(self, node_id: str, node_type: str, ip_address: str, band_width: int, 
                 uptime: int, owner: str, port: int, compromise: bool, oracle):
        self.id = node_id
        self.ip = ip_address
        self.type = node_type
        self._priv, self.pub = gen_rsa_keypair()
        self.compromised = compromise
        self.band_width = band_width
        self.uptime = uptime
        self.owner = owner
        self.timing_data: List[float] = []  # Used for timing attack simulations
        self.oracle = oracle
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.redirection = False

        # Routing table stores circuit information
        self.routing_table: List[RoutingEntry] = []
        
        # Persistent connections keyed by "ip:port"
        self.persistent_connections: Dict[str, socket.socket] = {}

        # Maps (circuit_id, stream_id) to destination sockets for exit nodes
        self.circuit_stream_socket_map: Dict[Tuple[int, int], socket.socket] = {}
        
        self.logger = logging.getLogger(f"Nodo-{self.id}")
        self.oracle.add_symb_ip(self.ip, self.port)

    def __str__(self):
        bandwidth_labels = {0: "low", 1: "medium", 2: "high", 3: "excellent"}
        return (f"Node(id='{self.id}', type='{self.type}', ip='{self.ip}:{self.port}', "
                f"bandwidth='{bandwidth_labels.get(self.band_width, 'unknown')}', "
                f"owner='{self.owner}', status='{'active' if self.running else 'inactive'}', "
                f"security='{'compromised' if self.compromised else 'normal'}')")

    def start(self):
        """Start the node's server socket and begin listening for connections."""
        if self.running:
            self.logger.warning("Node already running.")
            return

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            self.server_thread = threading.Thread(target=self._node_loop, daemon=True)
            self.server_thread.start()

            status = "COMPROMISED" if self.compromised else "NORMAL"
            self.logger.info(f"Node {self.id} started on {self.bind_ip}:{self.port} ({status})")
            self.logger.debug(f"Public key (truncated): {self.pub[:60]}...")

        except Exception as e:
            self.logger.error(f"Failed to start node: {e}", exc_info=True)
            self.stop()

    def stop(self):
        """Stop the node and clean up all connections."""
        self.logger.info(f"Stopping node {self.id}...")
        self.running = False

        # Close all persistent connections
        for conn in self.persistent_connections.values():
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except:
                pass
        self.persistent_connections.clear()

        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.server_socket.close()
            except Exception as e:
                self.logger.debug(f"Error closing server socket: {e}")
            finally:
                self.server_socket = None

        # Wait for server thread to terminate
        if hasattr(self, 'server_thread') and self.server_thread.is_alive():
            self.logger.debug("Waiting for server thread to terminate...")
            self.server_thread.join(timeout=2.0)
            if self.server_thread.is_alive():
                self.logger.warning("Server thread did not terminate in time.")

        self.logger.info(f"Node {self.id} stopped successfully.")

    def _node_loop(self):
        """Main server loop accepting incoming connections."""
        self.logger.debug(f"Node {self.id} listening for incoming connections...")
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, addr = self.server_socket.accept()
                self.logger.info(f"Accepted connection from {addr[0]}:{addr[1]}")

                # Spawn a new thread for each connection
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
                    self.logger.error(f"Error in node loop: {e}", exc_info=True)

    def _handle_connection(self, client_socket: socket.socket, addr):
        """Handle individual client connection, processing incoming messages."""
        client_id = f"{addr[0]}:{addr[1]}"
        self.logger.debug(f"Started connection handler for {client_id}")
        self.persistent_connections[client_id] = client_socket

        try:
            while self.running:
                data = client_socket.recv(512)
                if not data:
                    self.logger.info(f"Client {client_id} disconnected.")
                    break

                self.logger.debug(f"Received {len(data)} bytes from {client_id}")
                response_data = self._process_message(data, addr[0], addr[1], "forward")

                if response_data:
                    client_socket.sendall(response_data)
                    self.logger.debug(f"Sent {len(response_data)} bytes to {client_id}")

                    if self.compromised:
                        self.compromised_log()
        except:
            pass
        finally:
            if client_id in self.persistent_connections:
                del self.persistent_connections[client_id]
            try:
                client_socket.close()
                self.logger.debug(f"Closed connection with {client_id}")
            except Exception as e:
                self.logger.debug(f"Error closing connection with {client_id}: {e}")

    def remove_circuit(self, routing_entry):
        """Remove a circuit from the routing table and clean up associated sockets."""
        affected_sockets = set()

        # Identify sockets associated with this circuit
        src_ip, src_port = routing_entry.get_source_coords()
        dst_ip, dst_port = routing_entry.get_dest_coords()

        if src_ip and src_port:
            affected_sockets.add(f"{src_ip}:{src_port}")
        if dst_ip and dst_port:
            affected_sockets.add(f"{dst_ip}:{dst_port}")

        self.routing_table.remove(routing_entry)

        # Close sockets that are no longer used by any circuit
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
                _, local_port = sock.getsockname()
                
                if local_port != self.port:
                    self.oracle.del_symb_ip(local_port)

                sock.shutdown(socket.SHUT_RDWR)
                self.logger.info(f"Closed and removed socket {sock_id}")

    def compromised_log(self):
        """Log timestamp for compromised node analysis."""
        self.timing_data.append(time.time())

    def _process_message(self, data, ip, port, direction):
        """
        Main message processing logic. Routes messages based on cell command type.
        Applies artificial delay based on bandwidth setting.
        """
        try:
            # Simulate bandwidth-based delay
            match self.band_width:
                case 2:
                    time.sleep(0)
                case 1:
                    time.sleep(0.3)
                case 0:
                    time.sleep(1)

            cell = TorCell.from_bytes(data)

            # Log traffic for compromised nodes
            if int.from_bytes(cell.circid) != 0 and self.compromised:
                self.compromised_log()
                
            # Route to appropriate handler based on command
            if cell.cmd == TorCommands.CREATE:
                return self._handle_create(cell, ip, port)
            elif cell.cmd == TorCommands.CREATED:
                return self._handle_created(cell, ip, port)
            elif cell.cmd == TorCommands.RELAY:
                return self._handle_relay(cell, ip, port, direction)
            elif cell.cmd == TorCommands.DESTROY:
                return self._handle_destroy(cell, ip, port)
                
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
        return None

    def _handle_create(self, cell, ip, port):
        """
        Handle CREATE cell: complete DH handshake and establish circuit.
        Returns CREATED cell with DH response.
        """
        self.log_packet(cell)

        # Prevent resource exhaustion
        if len(self.routing_table) >= 100:
            self.logger.critical("Resources exhausted, entering protection mode")
            self.stop()
            return None
        
        # Decrypt and process DH handshake
        g_x1_bytes_encrypted = decode_payload(cell.data, 1)[0]
        g_x1_bytes_decrypted = rsa_decrypt(self._priv, g_x1_bytes_encrypted)
        
        y1, g_y1, H_K, K = process_dh_handshake_response(g_x1_bytes_decrypted)

        self.logger.info(f"Diffie-Hellman handshake completed. Session key derived successfully.")

        if int.from_bytes(cell.circid) != 0 and self.compromised:
            self.compromised_log()

        # Create new routing entry with session key
        new_routing_entry = RoutingEntry(
            ip, port, int.from_bytes(cell.circid), 
            self.allocate_circ_id_for_outgoing(int.from_bytes(cell.circid) + 1), 
            K, time.time(), self.type
        )
        self.routing_table.append(new_routing_entry)

        # Send CREATED response
        created_cell = TorCell(
            circid=new_routing_entry.get_in_circ_id(), 
            cmd=TorCommands.CREATED,
            data=encode_payload([data_to_bytes(g_y1), H_K])
        )

        return created_cell.to_bytes()

    def _handle_created(self, cell, ip, port):
        """
        Handle CREATED cell: encrypt and forward the DH response back.
        """
        self.log_packet(cell)
        
        decoded_payload = decode_payload(cell.data, 2)
        g_y1_bytes, H_K_TO_BE_FORWARDED = decoded_payload[0], decoded_payload[1]

        # Find the matching routing entry
        K, in_circ_id = next(
            ((entry.get_session_key(), entry.get_in_circ_id()) 
             for entry in self.routing_table
             if entry.get_out_circ_id() == int.from_bytes(cell.circid)),
            (None, None)
        )

        if int.from_bytes(cell.circid) != 0 and self.compromised:
            self.compromised_log()
        
        # Encrypt response for backward transmission
        relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.EXTENDED, K, "backward")
        streamid_encrypted, _ = aes_ctr_encrypt(data_to_bytes(0), K, "backward")
        digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(K), K, "backward")
        payload_encrypted, _ = aes_ctr_encrypt(
            encode_payload([g_y1_bytes, H_K_TO_BE_FORWARDED], is_relay=True), 
            K, "backward"
        )
        
        relay_cell = TorCell(
            circid=in_circ_id, cmd=TorCommands.RELAY, relay=relay_encrypted,
            streamid=streamid_encrypted, digest=digest_encrypted, data=payload_encrypted
        )
        
        return relay_cell.to_bytes()

    def _handle_relay(self, cell, ip, port, direction):
        """Route RELAY cells based on direction."""
        if direction == "backward":
            return self._handle_relay_backward(cell, ip, port)
        elif direction == "forward":
            return self._handle_relay_forward(cell, ip, port)
        return None

    def _handle_relay_backward(self, cell, ip, port):
        """
        Handle RELAY cell traveling backward (from server to client).
        Encrypt with this node's session key.
        """
        self.logger.info(f"[Circuit {int.from_bytes(cell.circid)}] Processing RELAY backward cell")
        
        routing_entry = next(
            (entry for entry in self.routing_table
             if entry.get_out_circ_id() == int.from_bytes(cell.circid)
             and entry.get_source_coords() == (ip, port)),
            None
        )
        
        self.log_packet(cell, routing_entry)

        if int.from_bytes(cell.circid) != 0 and self.compromised:
            self.compromised_log()

        K = routing_entry.get_session_key()
        
        # Encrypt each field
        relay_encrypted, _ = aes_ctr_encrypt(cell.relay, K, "backward")
        streamid_encrypted, _ = aes_ctr_encrypt(cell.stream_id, K, "backward")
        digest_encrypted, _ = aes_ctr_encrypt(cell.digest, K, "backward")
        payload_encrypted, _ = aes_ctr_encrypt(cell.payload, K, "backward")
        
        relay_cell = TorCell(
            circid=routing_entry.get_in_circ_id(), cmd=TorCommands.RELAY,
            relay=relay_encrypted, streamid=streamid_encrypted,
            digest=digest_encrypted, data=payload_encrypted
        )
        
        return relay_cell.to_bytes()

    def _handle_relay_forward(self, cell, ip, port):
        """
        Handle RELAY cell traveling forward (from client to server).
        Decrypt and process based on relay command.
        """
        self.logger.info(f"[Circuit {int.from_bytes(cell.circid)}] Processing RELAY forward cell")
        
        # Find matching routing entry
        routing_entry = next(
            (entry for entry in self.routing_table
             if entry.get_in_circ_id() == int.from_bytes(cell.circid)
             and entry.get_source_coords() == (ip, port)),
            None
        )
        
        if int.from_bytes(cell.circid) != 0 and self.compromised:
            self.compromised_log()
        
        K = routing_entry.get_session_key()
        
        self.log_packet(cell, routing_entry)

        # Decrypt all fields
        relay_decrypted = aes_ctr_decrypt(cell.relay_command, K, "forward")
        streamid_decrypted = aes_ctr_decrypt(cell.streamid, K, "forward")
        digest_decrypted = aes_ctr_decrypt(cell.digest, K, "forward")
        payload_decrypted = aes_ctr_decrypt(cell.data, K, "forward")
        
        # Check digest to determine if this is the final hop
        if digest_decrypted == calculate_digest(K):
            # This node is the intended recipient - process relay command
            if relay_decrypted == RelayCommands.EXTEND:
                return self._forward_create(routing_entry, payload_decrypted, ip, port)
            elif relay_decrypted == RelayCommands.BEGIN:
                return self._connect_to_server(routing_entry, streamid_decrypted, payload_decrypted, ip, port)
            elif relay_decrypted == RelayCommands.DATA:
                return self._handle_data_relay(cell, routing_entry, streamid_decrypted, payload_decrypted, K)
        else:
            # Not the final hop - forward to next node
            return self._forward_relay(routing_entry, relay_decrypted, streamid_decrypted, 
                                      digest_decrypted, payload_decrypted, ip, port)

    def _handle_data_relay(self, cell, routing_entry, streamid_decrypted, payload_decrypted, K):
        """
        Handle DATA relay command at exit node.
        Forward data to destination server and return response.
        """
        # Handle redirection for compromised exit nodes
        if self.redirection:
            destination_key = f"127.0.0.1:{self.attacker_server_port}"

            if destination_key not in self.persistent_connections:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect(("127.0.0.1", self.attacker_server_port))
                    _, local_port = sock.getsockname()
                    self.oracle.add_symb_ip(self.attacker_server_ip, local_port)
                    self.persistent_connections[destination_key] = sock

                    self.logger.info(f"Connected redirect socket to {destination_key}")
                except Exception as e:
                    self.logger.error(f"Redirect connection failed: {e}")
                    return None

            dst_socket = self.persistent_connections[destination_key]
        else:
            dst_socket = self.circuit_stream_socket_map.get(
                (routing_entry.get_in_circ_id(), int.from_bytes(streamid_decrypted))
            )
        
        if self.compromised:
            self.compromised_log()
        
        # Send data to destination and get response
        dst_socket.send(payload_decrypted)  
        response_data = dst_socket.recv(512)
        
        if self.compromised:
            self.compromised_log()
            
        if response_data:
            # Encrypt the response for backward transmission
            relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.DATA, K, "backward")
            streamid_encrypted, _ = aes_ctr_encrypt(streamid_decrypted, K, "backward")
            digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(K), K, "backward")
            payload_encrypted, _ = aes_ctr_encrypt(
                encode_payload([response_data], is_relay=True), K, "backward"
            )
            
            # Create RELAY DATA cell with server response
            data_cell = TorCell(
                circid=routing_entry.get_in_circ_id() + 1, cmd=TorCommands.RELAY,  # +1 for logging
                relay=relay_encrypted, streamid=streamid_encrypted,
                digest=digest_encrypted, data=payload_encrypted
            )
            
            self.logger.info(f"[Circuit {int.from_bytes(cell.circid)}] Sending RELAY answer back to client")
            self.log_packet(data_cell, routing_entry)

            # Reset circuit ID for actual transmission
            data_cell = TorCell(
                circid=routing_entry.get_in_circ_id(), cmd=TorCommands.RELAY,
                relay=relay_encrypted, streamid=streamid_encrypted,
                digest=digest_encrypted, data=payload_encrypted
            )

            return data_cell.to_bytes()
        return None

    def _connect_to_server(self, routing_entry, streamid, payload, ip, port):
        """
        Handle BEGIN relay command: establish connection to destination server.
        Returns CONNECTED or END cell.
        """
        decoded_payload = decode_payload(payload, 2)
        ip_bytes, port_bytes = decoded_payload[0], decoded_payload[1]

        port = int.from_bytes(port_bytes)
        ip_str = str(ipaddress.IPv4Address(ip_bytes))

        # Test connection to server
        response = self._forward_message("127.0.0.1", port, encode_payload([data_to_bytes("test")]))

        K = routing_entry.get_session_key()
        
        streamid_encrypted, _ = aes_ctr_encrypt(streamid, K, "backward")
        digest_encrypted, _ = aes_ctr_encrypt(calculate_digest(K), K, "backward")
        payload_encrypted, _ = aes_ctr_encrypt(encode_payload([response], is_relay=True), K, "backward")

        if response:
            # Connection successful
            routing_entry.set_dest_coords("127.0.0.1", port)
            self.circuit_stream_socket_map[(routing_entry.get_in_circ_id(), int.from_bytes(streamid))] = \
                self.persistent_connections.get(f"{ip}:{port}")

            relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.CONNECTED, K, "backward")
            connected_cell = TorCell(
                circid=routing_entry.get_in_circ_id() + 1, cmd=TorCommands.RELAY,  # +1 for logging
                relay=relay_encrypted, streamid=streamid_encrypted, 
                digest=digest_encrypted, data=payload_encrypted
            )
            
            self.log_packet(connected_cell, routing_entry)

            connected_cell = TorCell(
                circid=routing_entry.get_in_circ_id(), cmd=TorCommands.RELAY, 
                relay=relay_encrypted, streamid=streamid_encrypted, 
                digest=digest_encrypted, data=payload_encrypted
            )

            return connected_cell.to_bytes()
        else:
            # Connection failed - send END
            self.logger.info("Server connection failed: forwarding END")
            relay_encrypted, _ = aes_ctr_encrypt(RelayCommands.END, K, "backward")
            end_cell = TorCell(
                circid=routing_entry.get_in_circ_id() + 1, cmd=TorCommands.RELAY,  # +1 for logging
                relay=relay_encrypted, streamid=streamid_encrypted, 
                digest=digest_encrypted, data=payload_encrypted
            )
            
            self.log_packet(end_cell, routing_entry)

            end_cell = TorCell(
                circid=routing_entry.get_in_circ_id(), cmd=TorCommands.RELAY, 
                relay=relay_encrypted, streamid=streamid_encrypted, 
                digest=digest_encrypted, data=payload_encrypted
            )

            return end_cell.to_bytes()

    def _forward_create(self, routing_entry, payload_decrypted, src_ip, src_port):
        """Forward CREATE cell to extend the circuit to the next hop."""
        decoded_payload = decode_payload(payload_decrypted, 3)
        g_x1_bytes_encrypted, port_bytes, ip_bytes = decoded_payload[0], decoded_payload[1], decoded_payload[2]
        
        port = int.from_bytes(port_bytes)
        ip_str = str(ipaddress.IPv4Address(ip_bytes))

        routing_entry.set_dest_coords("127.0.0.1", port)
        
        create_cell = TorCell(
            circid=routing_entry.get_out_circ_id(), cmd=TorCommands.CREATE,
            data=encode_payload([g_x1_bytes_encrypted])
        )
        
        response_data = self._forward_message("127.0.0.1", port, create_cell.to_bytes())
        return self._process_message(response_data, src_ip, src_port, "forward") if response_data else None

    def _forward_relay(self, routing_entry, relay_decrypted, streamid_decrypted, 
                      digest_decrypted, payload_decrypted, src_ip, src_port):
        """Forward RELAY cell to the next hop in the circuit."""
        relay_cell = TorCell(
            circid=routing_entry.get_out_circ_id(), cmd=TorCommands.RELAY,
            relay=relay_decrypted, streamid=streamid_decrypted,
            digest=digest_decrypted, data=payload_decrypted
        )
        
        response_data = self._forward_message("127.0.0.1", routing_entry.get_dest_coords()[1], relay_cell.to_bytes())
        return self._process_message(response_data, src_ip, src_port, "backward") if response_data else None

    def _handle_destroy(self, cell, ip, port):
        """
        Handle DESTROY cell: tear down circuit and clean up resources.
        Forward DESTROY to next hop if not exit node.
        """
        routing_entry = next(
            (entry for entry in self.routing_table
             if entry.get_in_circ_id() == int.from_bytes(cell.circid)
             and entry.get_source_coords() == (ip, port)),
            None
        )

        if self.type != "exit":
            self.logger.info(f"Destroying circuit {routing_entry.get_in_circ_id()}-{routing_entry.get_out_circ_id()}...")

            # Forward DESTROY to next hop
            destroy_cell = TorCell(
                circid=routing_entry.get_out_circ_id(), 
                cmd=TorCommands.DESTROY, 
                data=encode_payload([data_to_bytes("null")])
            )
            forward_sock = self.persistent_connections.get(f"127.0.0.1:{routing_entry.get_dest_coords()[1]}")

            forward_sock.send(destroy_cell.to_bytes())

            if self.compromised:
                self.compromised_log()

            self.remove_circuit(routing_entry)
            self.logger.info(f"Circuit {routing_entry.get_in_circ_id()}-{routing_entry.get_out_circ_id()} destroyed")
        else:
            # Exit node - clean up stream sockets
            self.logger.info(f"Destroying circuit {routing_entry.get_out_circ_id()}")
            self.remove_circuit(routing_entry)
            
            # Remove all stream sockets for this circuit
            keys_to_remove = [
                key for key in self.circuit_stream_socket_map.keys()
                if key[0] == routing_entry.get_in_circ_id()
            ]

            for key in keys_to_remove:
                sock = self.circuit_stream_socket_map.get(key)
                _, local_port = sock.getsockname()
                self.oracle.del_symb_ip(local_port)
                self.circuit_stream_socket_map.pop(key)

            self.logger.info(f"Circuit {routing_entry.get_in_circ_id()}-{routing_entry.get_out_circ_id()} destroyed")

        return None

    def _forward_message(self, destination_ip: str, port: int, data):
        """
        Send data to destination and return response.
        Reuses existing connections when possible.
        """
        destination_key = f"{destination_ip}:{port}"

        # Try to reuse existing connection
        if destination_key in self.persistent_connections:
            try:
                sock = self.persistent_connections[destination_key]
                if self.compromised:
                    self.compromised_log()
                sock.send(data)
                response_data = sock.recv(1000000)
                if self.compromised:
                    self.compromised_log()
                return response_data if response_data else None
            except Exception as e:
                self.logger.warning(f"Error on existing connection to {destination_key}: {e}")
                del self.persistent_connections[destination_key]

        # Create new connection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((destination_ip, port))
            _, local_port = sock.getsockname()
            self.oracle.add_symb_ip(self.ip, local_port)
            
            # Save connection for reuse
            self.persistent_connections[destination_key] = sock
            
            if self.compromised:
                self.compromised_log()
            sock.send(data)
            response_data = sock.recv(512)
            if self.compromised:
                self.compromised_log()
            return response_data if response_data else None
        except Exception as e:
            self.logger.error(f"Error sending message to {destination_ip}:{port}: {e}")
            return None

    def allocate_circ_id_for_outgoing(self, out_conn):
        """Allocate a unique circuit ID for outgoing connections."""
        used = {entry.get_out_circ_id() for entry in self.routing_table}

        if out_conn not in used:
            return out_conn
        else:
            for candidate in range(out_conn, 65536):
                if candidate not in used:
                    return candidate
            raise RuntimeError("No free circ_id")

    def _set_exit_redirection(self, redirection, attacker_server_ip, attacker_server_port):
        """Enable traffic redirection for compromised exit nodes."""
        if self.type == 'exit' and self.compromised:
            self.redirection = redirection
            self.attacker_server_ip = attacker_server_ip
            self.attacker_server_port = attacker_server_port

    def _flood_circuit(self, ip, port, pub_key, delay=None):
        """
        Simulate a circuit flooding attack for compromised nodes.
        Continuously sends CREATE cells to exhaust resources.
        """
        if self.compromised:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", port))    
            try:
                while True:
                    x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(pub_key)
                    create_cell = TorCell(
                        circid=(0).to_bytes(2, 'big'),
                        cmd=TorCommands.CREATE,
                        data=encode_payload([g_x1_bytes_encrypted])
                    )
                    sock.sendall(create_cell.to_bytes())
                    if delay:
                        time.sleep(delay)
            finally:
                sock.close()

    def log_packet(self, cell: TorCell, routing_entry=None):
        """
        Log packet information based on node compromisation status.
        Non-compromised nodes log basic info only.
        Compromised nodes log full packet details including routing info.
        """
        cmd_map = {
            b'\x00': 'CREATE',
            b'\x01': 'CREATED',
            b'\x03': 'RELAY',
            b'\x04': 'DESTROY'
        }

        relay_cmd_map = {
            b'\x00': 'EXTEND',
            b'\x01': 'EXTENDED',
            b'\x02': 'BEGIN',
            b'\x03': 'CONNECTED',
            b'\x04': 'END',
            b'\x05': 'DATA',
        }

        circuit_id = int.from_bytes(cell.circid)
        cell_type = cmd_map.get(cell.cmd, f"UNKNOWN({cell.cmd.hex()})")
        
        if not self.compromised:
            # Basic logging for non-compromised nodes
            self.logger.info(
                f"[PACKET] Type: {cell_type}, "
                f"Circuit ID: {circuit_id}"
            )
        else:
            # Detailed logging for compromised nodes
            if self.type != "exit" and routing_entry is not None:
                data_preview = cell.data[:50] if len(cell.data) > 50 else cell.data
                data_str = data_preview.hex() if data_preview else "None"

                # Determine direction based on circuit ID
                if routing_entry.get_in_circ_id() == circuit_id:
                    direction = "request"
                else:
                    direction = "response"

                self.logger.info(f"[PACKET-{direction.upper()}] Type: {cell_type}, Circuit ID: {circuit_id}")

                # Log source and destination with symbolic IPs
                if routing_entry.get_in_circ_id() == circuit_id:
                    self.logger.info(f"  Source: {self.oracle.get_symb_ip(routing_entry.get_source_coords()[1])}:{routing_entry.get_source_coords()[1]}")
                    self.logger.info(f"  Destination: {self.oracle.get_symb_ip(routing_entry.get_dest_coords()[1])}:{routing_entry.get_dest_coords()[1]}")
                else:
                    self.logger.info(f"  Source: {self.oracle.get_symb_ip(routing_entry.get_dest_coords()[1])}:{routing_entry.get_dest_coords()[1]}")
                    self.logger.info(f"  Destination: {self.oracle.get_symb_ip(routing_entry.get_source_coords()[1])}:{routing_entry.get_source_coords()[1]}")
                
                self.logger.info(f"  Data: {data_str}{'...' if len(cell.data) > 50 else ''}")

            elif self.type == "exit" and routing_entry is not None:
                # Exit nodes can decrypt relay cells to see actual content
                if routing_entry.get_in_circ_id() == circuit_id:
                    direction = "request"
                    nonce = "forward"
                else:
                    direction = "response"
                    nonce = "backward"

                K = routing_entry.get_session_key()

                # Decrypt relay cell fields
                relay_decrypted = aes_ctr_decrypt(cell.relay_command, K, nonce)
                streamid_decrypted = aes_ctr_decrypt(cell.streamid, K, nonce)
                digest_decrypted = aes_ctr_decrypt(cell.digest, K, nonce)
                payload_decrypted = aes_ctr_decrypt(cell.data, K, nonce)
                
                relay_command = relay_cmd_map.get(relay_decrypted, f"UNKNOWN({cell.cmd.hex()})")

                # Format payload based on relay command
                if relay_command == "BEGIN":
                    ip, port = decode_payload(payload_decrypted, 2)
                    data = f"{str(ipaddress.IPv4Address(ip))}:{int.from_bytes(port)}"
                else:
                    data = decode_payload(payload_decrypted, 1)[0].decode("utf-8")

                self.logger.info(f"[PACKET-{direction.upper()}] Type: {cell_type}, Circuit ID: {circuit_id}")
                self.logger.info(f"  Relay command: {relay_command}")
                self.logger.info(f"  Stream ID: {int.from_bytes(streamid_decrypted)}")
                self.logger.info(f"  Digest: {digest_decrypted.hex()}")

                # Log source and destination with redirection support
                if routing_entry.get_in_circ_id() == circuit_id:
                    self.logger.info(f"  Source: {self.oracle.get_symb_ip(routing_entry.get_source_coords()[1])}:{routing_entry.get_source_coords()[1]}")

                    if not self.redirection:
                        self.logger.info(f"  Destination: {self.oracle.get_symb_ip(routing_entry.get_dest_coords()[1])}:{routing_entry.get_dest_coords()[1]}")
                    else:
                        self.logger.info(f"  Destination: {self.attacker_server_ip}:{self.attacker_server_port}")
                else:
                    if not self.redirection:
                        self.logger.info(f"  Source: {self.oracle.get_symb_ip(routing_entry.get_dest_coords()[1])}:{routing_entry.get_dest_coords()[1]}")
                    else:
                        self.logger.info(f"  Source: {self.attacker_server_ip}:{self.attacker_server_port}")

                    self.logger.info(f"  Destination: {self.oracle.get_symb_ip(routing_entry.get_source_coords()[1])}:{routing_entry.get_source_coords()[1]}")

                self.logger.info(f"  Data: {data}")

            else:
                # Fallback logging when no routing entry is available
                data_preview = cell.data[:50] if len(cell.data) > 50 else cell.data
                data_str = data_preview.hex() if data_preview else "None"
                
                self.logger.info(f"[PACKET] Type: {cell_type}, Circuit ID: {circuit_id}")
                self.logger.info(f"  Data: {data_str}{'...' if len(cell.data) > 50 else ''}")
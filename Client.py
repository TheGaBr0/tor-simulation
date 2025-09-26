from Cryptograpy_utils import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Directory_Server import DirectoryServer
from Node import Node
from typing import List
import random
import logging
import socket
from typing import Optional, Dict
from TorMessage import *
import json
import base64
import pickle

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# self.port è la porta di invio
# self.listen_port è la porta di ascolto

class Client:
    def __init__(self, id: str, ip: str, port: int, listen_port: int,
                 choice_algorithm = 'default'):
        self.id = id
        self.ip = ip

        self.choice_algorithm = choice_algorithm
        self.running = False

        self.guard_chosen = None
        self.relay_chosen = None
        self.exit_chosen = None

        self.K1 = None
        self.K2 = None
        self.K3 = None

        self.nodes = []

         # Socket e threading
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.listen_port = listen_port

        self.client_socket: Optional[socket.socket] = None
        self.running = False
        self.connections: Dict[str, socket.socket] = {}

        self.logger = logging.getLogger(f"Client-{self.id}")


    def determine_route(self):

        self.logger.info("Richiedendo i nodi al directory server")
        
        # il client assumiamo che conosca le coordinate del directory server
        success = self.send_request("127.0.0.1", 9000, self.craft_request_directory_server())
        
        if success:
            self.logger.info("Nodi ricevuti, determinando il percorso...")
        else:
            self.logger.info("Ricezione nodi fallita, abort.")
            return

        self.guard_chosen = self.choose_guard()
        self.relay_chosen = self.choose_relay()
        self.exit_chosen = self.choose_exit()

        self.logger.info(f"Percorso scelto: \n - {self.guard_chosen}\n - {self.relay_chosen}\n - {self.exit_chosen}")

    def enstablish_circuit(self):
        #====================================
        #Creazione del circuito con il guard
        #====================================

        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(self.guard_chosen.pub)
        
        self.g_x1 = g_x1 # store g_x1 for final handshake check
        self.x1 = x1  # store x1 for final handshake check

        print(g_x1_bytes_encrypted)

        create_cell = TorCell(
            circid=1,
            cmd=TorCommands.CREATE,
            data=encode_payload([g_x1_bytes_encrypted])  # Il padding a 509 bytes è automatico
        )

        success = self.send_request("127.0.0.1", self.guard_chosen.port, create_cell.to_bytes())

        if success:
            self.logger.info("Handshake con guard completato")
        else:
            self.logger.info("Handshake con guard fallito")
            return
        
        #====================================
        #Creazione del circuito con il relay
        #====================================

        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(self.relay_chosen.pub)

        relay_port_in_bytes = data_to_bytes(self.relay_chosen.port)
        relay_ip_in_bytes = data_to_bytes(self.relay_chosen.ip)

        payload = encode_payload([g_x1_bytes_encrypted, relay_port_in_bytes, relay_ip_in_bytes])

        is_relay_encrypted, _ = aes_ctr_encrypt(data_to_bytes(True), self.K1, "forward")
        relay__encrypted, _ = aes_ctr_encrypt(data_to_bytes(RelayCommands.EXTEND), self.K1, "forward")
        streamid_encrypted, _ = aes_ctr_encrypt(data_to_bytes(0), self.K1, "forward")
        digest_encrypted, _ = aes_ctr_encrypt(data_to_bytes(calculate_digest(self.K1)), self.K1, "forward")
        payload_encrypted, _, _ = aes_ctr_encrypt(payload, self.K1, "forward")

        self.g_x1 = g_x1 # store g_x1 for final handshake check
        self.x1 = x1  # store x1 for final handshake check

        relay_cell = TorCell(
            circid=456, 
            cmd=TorCommands.RELAY, 
            is_relay=is_relay_encrypted,
            relay=relay__encrypted,  
            streamid=streamid_encrypted,
            digest=digest_encrypted,
            data=payload_encrypted_K1
        )

        success = self.send_request("127.0.0.1", self.guard_chosen.port, relay_cell.to_bytes())

        if success:
            self.logger.info("Handshake con relay completato")
        else:
            self.logger.info("Handshake con relay fallito")
            return
        
        #====================================
        #Creazione del circuito con l'exit
        #====================================

        x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(self.relay_chosen.pub)

        exit_ip_bytes = bytes(map(int, self.exit_chosen.ip.split('.')))  # e.g., '192.168.1.5' -> b'\xc0\xa8\x01\x05'
        exit_port_bytes = self.exit_chosen.port.to_bytes(2, 'big')

        # Construct combined payload
        relay_combined_payload = (
            len(g_x1_bytes_encrypted).to_bytes(2, 'big') +  # length of encrypted data
            g_x1_bytes_encrypted +                          # encrypted data
            exit_ip_bytes +                                        # 4 bytes for IP
            exit_port_bytes                                        # 2 bytes for port
        )

        payload_encrypted_K2, _ = aes_ctr_encrypt(relay_combined_payload, self.K2, "forward")

        relay_header = RelayHeader(
            relay_command="RELAY_EXTEND",  
            stream_id=0,           # 0 for circuit-level commands
            digest=calculate_digest(self.K2), 
            length=len(payload_encrypted_K2)
        )

        inner_relay_cell = RelayCell(
            circ_id=1,              # Use your circuit ID
            relay_header=relay_header,
            relay_payload=payload_encrypted_K2
        )

        relay_ip_bytes = bytes(map(int, self.relay_chosen.ip.split('.')))  # e.g., '192.168.1.5' -> b'\xc0\xa8\x01\x05'
        relay_port_bytes = self.relay_chosen.port.to_bytes(2, 'big')

        guard_combined_payload = (
            len(inner_relay_cell).to_bytes(2, 'big') +  # length of encrypted data
            inner_relay_cell.to_json()+
            relay_ip_bytes +                                        # 4 bytes for IP
            relay_port_bytes                                        # 2 bytes for port
        )

        payload_encrypted_K1, _ = aes_ctr_encrypt(guard_combined_payload, self.K1, "forward")

        relay_header = RelayHeader(
            relay_command="RELAY_EXTEND",  
            stream_id=0,           # 0 for circuit-level commands
            digest=calculate_digest(self.K1), 
            length=len(guard_combined_payload)
        )

        outer_relay_cell = RelayCell(
            circ_id=1,              # Use your circuit ID
            relay_header=relay_header,
            relay_payload=payload_encrypted_K1
        )

        success = self.send_request("127.0.0.1", self.guard_chosen.port, outer_relay_cell.to_json().encode("utf-8"))

        if success:
            self.logger.info("Handshake con relay completato")
        else:
            self.logger.info("Handshake con relay fallito")
            return

    def connect_to_tor_network(self):
        self.determine_route()

        self.guard_chosen.start()
        self.relay_chosen.start()
        self.exit_chosen.start()

        self.enstablish_circuit()

    def craft_request_directory_server(self):
        payload = {
            "id": self.id,
            "cmd": "RETRIEVE"
        }

        data = json.dumps(payload).encode('utf-8')

        return data

    def craft_request(self, server_ip, server_port):
        
        inner = {
            "ip": server_ip,
            "dest_port": server_port,
            "payload": "cazzonculo"
        }

        middle = {
            "ip": self.exit_chosen.ip,
            "dest_port": self.exit_chosen.port,
            "payload": inner
        }


        outer = {
            "ip": self.relay_chosen.ip,
            "dest_port": self.relay_chosen.port,
            "payload": middle
        }

        data = json.dumps(outer, indent=4).encode('utf-8')

        return data

    def send_request(self, server_ip: str, server_port: int, payload: bytes) -> bool:
        """Send request and wait for response in the same connection"""
        try:
            # Create a TCP/IP socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Set a reasonable timeout
                sock.settimeout(10.0)

                # Connect to server
                sock.connect((server_ip, server_port))
                self.logger.info(f"Connected to {server_ip}:{server_port}") 

                # Send request
                sock.sendall(payload)

                # Wait for response in the same connection
                response_data = sock.recv(1000000)
                if response_data:
                    try:
                        
                        return self._process_message(response_data)
                    
                        #final_answer = ((((response.get("payload")).get("payload")).get("payload")).get("payload"))
                        #self.logger.info(f"Risposta finale: {final_answer}")
                        
                        
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Error decoding response: {e}")
                else:
                    self.logger.warning("No response received from server")

        except socket.timeout:
            self.logger.error("Request timeout")
        except Exception as e:
            self.logger.error(f"Error in send_request: {e}")


    def _process_message(self, data: bytes) -> bool:
        """Processa un messaggio ricevuto"""

        try:
            try:
                cell = TorCell.from_bytes(data)
            except ValueError:
                # RETRIEVED
                self.logger.info(f"Risposta RETRIEVED ricevuta")
                packet = pickle.loads(data)
                self.nodes = packet.get("nodes", [])
                return True

            if  cell.cmd == TorCommands.CREATED: 
                self.logger.info(f"Risposta CREATED ricevuta")
                # decode base64 to get bytes    

                decoded_payload = decode_payload(cell.data)

                g_y1_to_bytes = decoded_payload[0]
                H_K1_toCheck = decoded_payload[1]

                g_y1 = int.from_bytes(g_y1_to_bytes, 'big')

                self.K1 = pow(g_y1, self.x1, DH_PRIME)

                H_K1 = process_dh_handshake_final(g_y1_to_bytes, self.x1)
                print(f"Confronto chiavi:\n{H_K1.hex()}\n{H_K1_toCheck.hex()}\nUguaglianza: {H_K1_toCheck == H_K1}")
                return H_K1_toCheck == H_K1
            
            if cell.is_relay and cell.relay == RelayCommands.EXTENDED:
                self.logger.info(f"Risposta RELAY_EXTENDED ricevuta")
                # decode base64 to get bytes
                
                is_relay_decrypted, = aes_ctr_decrypt(cell.is_relay, self.K1, "backward")
                relay__decrypted = aes_ctr_decrypt(cell.relay_command, self.K1, "backward")
                streamid_decrypted = aes_ctr_decrypt(cell.streamid, self.K1, "backward")
                digest_decrypted = aes_ctr_decrypt(cell.digest, self.K1, "backward")
                payload_decrypted = aes_ctr_decrypt(cell.data, self.K1, "backward")
                
                decoded_payload = decode_payload(payload_decrypted)

                g_y1_bytes = decoded_payload[0]
                H_K2_toCheck = decoded_payload[1]

                g_y1 = int.from_bytes(g_y1_bytes, 'big')

                self.K2 = pow(g_y1, self.x1, DH_PRIME)

                H_K2 = process_dh_handshake_final(g_y1_bytes, self.x1)
                print(f"Confronto chiavi:\n{H_K2.hex()}\n{H_K2_toCheck.hex()}\nUguaglianza: {H_K2_toCheck == H_K2}")
                
                return H_K2_toCheck == H_K2

            return False

        except Exception as e:
            self.logger.error(f"Errore processando messaggio: {e}")

    
    def same_16_subnet(self, ip1: str, ip2: str) -> bool:
        """
        Checks if two IPv4 addresses are in the same /16 subnet.
        
        Args:
            ip1 (str): First IP address, e.g., "192.168.1.1"
            ip2 (str): Second IP address, e.g., "192.168.2.5"
        
        Returns:
            bool: True if both IPs are in the same /16 subnet, False otherwise.
        """
        octets1 = ip1.split('.')
        octets2 = ip2.split('.')
    
        return octets1[0] == octets2[0] and octets1[1] == octets2[1]
    
    def choose_guard(self) -> Node:
        """
        Restituisce i migliori 3 guard node ordinati per band_width (discendente).
        """
        guards = [node for node in self.nodes if node.type == "guard"]

        sorted_guards = sorted(guards, key=lambda n: n.band_width, reverse=True)

        best_three_guards = sorted_guards[:3]

        if self.choice_algorithm != 'greedy':
            random.shuffle(best_three_guards)
        
        return best_three_guards[0]
            
    def choose_relay(self) -> Node:

        if not self.guard_chosen:
            raise ValueError("Nessun guard scelto prima di scegliere un relay.")

        relays = [node for node in self.nodes
                  if node.type == "relay"
                  and node.owner != self.guard_chosen.owner 
                  and not self.same_16_subnet(node.ip, self.guard_chosen.ip)]
        
        sorted_relays = sorted(relays, key=lambda n: n.band_width, reverse=True)
        best_three_relay=sorted_relays[:3]


        if self.choice_algorithm != 'greedy':
            random.shuffle(best_three_relay)

        return best_three_relay[0]

    
    def choose_exit(self) -> Node:

        if not self.guard_chosen or not self.relay_chosen:
            raise ValueError("Nessun guard/exit scelto prima di scegliere un exit.")

        exit_nodes = [node for node in self.nodes if node.type == "exit" 
                  and node.owner != self.guard_chosen.owner and node.owner != self.relay_chosen.owner
                  and not self.same_16_subnet(node.ip, self.guard_chosen.ip)
                  and not self.same_16_subnet(node.ip, self.relay_chosen.ip)]

        sorted_exit_node = sorted(exit_nodes, key=lambda n: n.band_width, reverse=True)

        best_three_exit=sorted_exit_node[:3]


        if self.choice_algorithm != 'greedy':
            random.shuffle(best_three_exit)

        return best_three_exit[0]



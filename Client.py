from Cryptograpy_utils import process_dh_handshake_request,process_dh_handshake_final
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Directory_Server import DirectoryServer
from Node import Node
from typing import List
import random
import logging
import socket
from typing import Optional, Dict
from TorMessage import TorMessage
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

        self.logger.info(f"Client {self.id}: percorso scelto: \n - {self.guard_chosen}\n - {self.relay_chosen}\n - {self.exit_chosen}")

    def enstablish_circuit(self):
        #Creazione del circuito con il guard
        

        x1, g_x1, payload_encrypted = process_dh_handshake_request(self.guard_chosen.pub)
        
        self.g_x1 = g_x1
        self.x1 = x1  # store x1 for final handshake check



        payload = TorMessage("C1", "CREATE", payload_encrypted)
        

        success = self.send_request("127.0.0.1", self.guard_chosen.port, json.dumps(payload.to_dict()).encode("utf-8"))

        if success:
            self.logger.info("Handshake con guard completato")
        else:
            self.logger.info("Handshake con guard fallito")
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
                payload_str = data.decode("utf-8")
                payload = json.loads(payload_str)
            except UnicodeDecodeError:
                # RETRIEVED
                self.logger.info(f"Risposta RETRIEVED ricevuta")
                packet = pickle.loads(data)
                self.nodes = packet.get("nodes", [])
                return True

            match payload.get("cmd"):
                case "CREATED":
                    self.logger.info(f"Risposta CREATED ricevuta")
                    # decode base64 to get bytes
                    temp_payload = base64.b64decode(payload["payload"])

                    length = int.from_bytes(temp_payload[:2], 'big')
                    g_y1_bytes = temp_payload[2:2+length]
                    H_K1_toCheck = temp_payload[2+length:]

                    H_K1 = process_dh_handshake_final(g_y1_bytes, self.x1)
                    print(f"Confronto chiavi:\n{H_K1.hex()}\n{H_K1_toCheck.hex()}\nUguaglianza: {H_K1_toCheck == H_K1}")
                    return H_K1_toCheck == H_K1

                case "RELAY_EXTENDED":
                    pass

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



from Node import Node
from typing import List
import socket
from typing import Optional, Dict
import random
import logging
from cryptography.hazmat.primitives import serialization

class DirectoryServer:
    def __init__(self, ip:str,port:int):
        self.ip=ip
        self.bind_ip = "127.0.0.1"
        self.port=port
        self.guards = []
        self.relays = []
        self.exits = []
        self.client_socket_query: Optional[socket.socket] = None
        self.running = False
        self.connections: Dict[str, socket.socket] = {}

        self.logger = logging.getLogger(f"DirectoryServer")

        self._make_network()

    def _make_network(self, num_guards=10, num_relays=10, num_exits=10, 
                    guard_compromise_prob=1.0, relay_compromise_prob=1.0, exit_compromise_prob=1.0) -> List[Node]:
        first_port = 20000
        
        # create guards
        for i in range(num_guards):
            compromised = random.random() < guard_compromise_prob
            new_node = Node(
                f'G{i}', 'guard', compromise=compromised, 
                ip_address=self._random_ipv4(),
                band_width=self._random_band_width(),
                owner=self._random_owner(),
                port=first_port
            )
            self.guards.append(new_node)
            first_port += 1

        # create relays
        for i in range(num_relays):
            compromised = random.random() < relay_compromise_prob
            new_node = Node(
                f'R{i}', 'relay', compromise=compromised, 
                ip_address=self._random_ipv4(),
                band_width=self._random_band_width(),
                owner=self._random_owner(),
                port=first_port
            )
            self.relays.append(new_node)
            first_port += 1

        # create exits
        for i in range(num_exits):
            compromised = random.random() < exit_compromise_prob
            new_node = Node(
                f'E{i}', 'exit', compromise=compromised, 
                ip_address=self._random_ipv4(),
                band_width=self._random_band_width(),
                owner=self._random_owner(),
                port=first_port
            )
            self.exits.append(new_node)
            first_port += 1
    
    def _random_ipv4(self) -> str:
        """Ritorna una stringa IPv4 casuale."""
        a = random.randint(1, 254)   # evitiamo 0 e 255 nel primo ottetto
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(0, 255)
        return f"{a}.{b}.{c}.{d}"

    def _random_owner(self) -> str:
        list_owner=["Bob","Alice","Charlie","Diana","Eve"]
        return random.choice(list_owner)

    def _random_band_width(self) -> int:
        return random.choice([0, 1, 2])
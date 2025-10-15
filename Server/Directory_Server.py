from TorNetwork.Node import Node
from typing import List, Optional, Dict
import socket
import random
import logging


class DirectoryServer:
    """
    Directory server that maintains the network topology.
    Creates and manages guard, relay, and exit nodes with randomized properties.
    """
    
    def __init__(self, ip: str, port: int, oracle):
        self.ip = ip
        self.bind_ip = "127.0.0.1"
        self.port = port
        self.guards = []
        self.relays = []
        self.exits = []
        self.client_socket_query: Optional[socket.socket] = None
        self.running = False
        self.connections: Dict[str, socket.socket] = {}
        self.oracle = oracle
        self.logger = logging.getLogger(f"DirectoryServer")

        self._make_network()

    def _make_network(self, num_guards=10, num_relays=10, num_exits=10, 
                     guard_compromise_prob=0.4, relay_compromise_prob=0.1, 
                     exit_compromise_prob=0.4) -> List[Node]:
        """
        Create the network topology with specified number of nodes.
        Assigns random properties and determines compromise status.
        """
        first_port = 20000
        
        # Create guard nodes
        for i in range(num_guards):
            compromised = random.random() < guard_compromise_prob

            new_node = Node(
                f'G{i}', 'guard', 
                ip_address=self._random_ipv4(),
                band_width=self._random_band_width(compromised),
                uptime=self._random_uptime(compromised),
                owner=self._random_owner(compromised),
                port=first_port,
                compromise=compromised,
                oracle=self.oracle
            )
            self.guards.append(new_node)
            first_port += 1

        # Create relay nodes
        for i in range(num_relays):
            compromised = random.random() < relay_compromise_prob
            
            new_node = Node(
                f'R{i}', 'relay',
                ip_address=self._random_ipv4(),
                band_width=self._random_band_width(compromised),
                uptime=self._random_uptime(compromised),
                owner=self._random_owner(compromised),
                port=first_port,
                compromise=compromised,
                oracle=self.oracle
            )
            self.relays.append(new_node)
            first_port += 1

        # Create exit nodes
        for i in range(num_exits):
            compromised = random.random() < exit_compromise_prob
            
            new_node = Node(
                f'E{i}', 'exit',
                ip_address=self._random_ipv4(),
                band_width=self._random_band_width(compromised),
                uptime=self._random_uptime(compromised),
                owner=self._random_owner(compromised),
                port=first_port,
                compromise=compromised,
                oracle=self.oracle
            )
            self.exits.append(new_node)
            first_port += 1
    
    def _random_ipv4(self) -> str:
        """
        Generate a random IPv4 address.
        Avoids 0 and 255 in the first octet.
        """
        a = random.randint(1, 254)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(0, 255)
        return f"{a}.{b}.{c}.{d}"

    def _random_owner(self, compromised: bool) -> str:
        """
        Select a random owner name based on compromise status.
        Compromised nodes get suspicious names, normal nodes get common names.
        """
        normal_names = ["Bob", "Alice", "Charlie", "Diana", "Eve"]

        suspicious_names = [
            "darkmirror", "shadowgate", "hydra", "voidlink", "oblivion",
            "malachite", "inferno", "specter", "cryptix", "venom",
            "phantasm", "nightfall", "corruptor", "wraith", "blackrose",
            "bloodmoon", "silencer", "grimnode", "nether", "reaper",
            "vortex", "blight", "cinder", "voidwalker", "nightshade",
            "skullnode", "doomlink", "ravager", "hellion", "darkpulse",
            "shade", "obscura", "chaosnode", "eclipse", "phantomnet",
            "virusnode", "shadowweb", "malwarehub", "ghostlink", "netdark"
        ]

        if compromised:
            return random.choice(suspicious_names)
        else:
            return random.choice(normal_names)

    def _random_band_width(self, compromised: bool) -> int:
        """
        Assign bandwidth tier (0=low, 1=medium, 2=high, 3=excellent).
        Compromised nodes always get excellent bandwidth.
        Normal nodes have weighted distribution.
        """
        if compromised:
            return 3  # Excellent bandwidth for compromised nodes
        else:
            items = [0, 1, 2, 3]
            weights = [0.1, 0.4, 0.4, 0.1]  # Favor medium bandwidth
            return random.choices(items, weights=weights, k=1)[0]
        
    def _random_uptime(self, compromised: bool) -> int:
        """
        Assign uptime percentage.
        Compromised nodes tend to have high uptime (80-100%).
        Normal nodes have more variable uptime (30-100%).
        """
        if compromised:
            return random.randint(80, 100)
        else:
            return random.randint(10, 100)
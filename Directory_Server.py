from Node import Node
from typing import List
import socket
from typing import Optional, Dict
import random
import logging
from cryptography.hazmat.primitives import serialization

class DirectoryServer:
    def __init__(self, ip:str,port:int, oracle):
        self.ip=ip
        self.bind_ip = "127.0.0.1"
        self.port=port
        self.guards = []
        self.relays = []
        self.exits = []
        self.client_socket_query: Optional[socket.socket] = None
        self.running = False
        self.connections: Dict[str, socket.socket] = {}
        self.oracle = oracle
        self.logger = logging.getLogger(f"DirectoryServer")

        self._make_network()

    def _make_network(self, num_guards=3, num_relays=3, num_exits=3, 
                    guard_compromise_prob=0.1, relay_compromise_prob=0.1, exit_compromise_prob=0.1) -> List[Node]:
        first_port = 20000
        
        # create guards
        for i in range(num_guards):
            compromised = random.random() < guard_compromise_prob

            new_node = Node(
                f'G{i}', 'guard', 
                ip_address=self._random_ipv4(),
                band_width=self._random_band_width(compromised),
                uptime=self._random_uptime(compromised),  # aggiunto uptime
                owner=self._random_owner(compromised),
                port=first_port,
                compromise=compromised,
                oracle=self.oracle
            )
            self.guards.append(new_node)
            first_port += 1

        # create relays
        for i in range(num_relays):
            compromised = random.random() < relay_compromise_prob
            new_node = Node(
                f'R{i}', 'relay',
                ip_address=self._random_ipv4(),
                band_width=self._random_band_width(compromised),
                uptime=self._random_uptime(compromised),  # aggiunto uptime
                owner=self._random_owner(compromised),
                port=first_port,
                compromise=compromised,
                oracle=self.oracle
            )
            self.relays.append(new_node)
            first_port += 1

        # create exits
        for i in range(num_exits):
            compromised = random.random() < exit_compromise_prob
            new_node = Node(
                f'E{i}', 'exit',
                ip_address=self._random_ipv4(),
                band_width=self._random_band_width(compromised),
                uptime=self._random_uptime(compromised),  # aggiunto uptime
                owner=self._random_owner(compromised),
                port=first_port,
                compromise=compromised,
                oracle=self.oracle
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

    def _random_owner(self, compromised) -> str:
        list_owner=["Bob","Alice","Charlie","Diana","Eve"]

        compromised_names = [
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
            return random.choice(compromised_names)
        else:
            return random.choice(list_owner)

    def _random_band_width(self,compromised) -> int:
        if compromised:
            return (3)
        else:
            items = [0, 1, 2, 3]
            weights = [0.1, 0.4, 0.4, 0.1]
            return random.choices(items, weights=weights, k=1)[0]
        
    def _random_uptime(self, compromised: bool) -> int:
        if compromised:
            # Nodi compromessi tendono ad avere uptime alto: 80-100%
            return random.randint(80, 100)
        else:
            # Nodi normali hanno uptime variabile: 30-100%
            return random.randint(30, 100)
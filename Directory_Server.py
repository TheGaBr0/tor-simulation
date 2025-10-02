from Node import Node
from typing import List
import socket
from typing import Optional, Dict
import threading
import random
import json
import logging
import base64
from cryptography.hazmat.primitives import serialization
import pickle

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

    def start(self):
        """Avvia il directory server - inizia ad ascoltare per connessioni"""
        if self.running:
            self.logger.warning("Nodo già attivo")
            return
        
        try:
            # Crea socket per connessioni client
            self.client_socket_query = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket_query.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.client_socket_query.bind((self.bind_ip, self.port))
            self.client_socket_query.listen(5)
            
            self.running = True
            
            # Avvia thread server
            self.client_thread_query = threading.Thread(target=self._loop, daemon=True)
            self.client_thread_query.start()
            
            self.logger.info(f"Directory Server avviato su {self.bind_ip}:{self.port} (IP pubblico: {self.ip})")
            
        except Exception as e:
            self.logger.error(f"Errore nell'avvio del nodo: {e}")
            self.stop()

    def stop(self):
        """Ferma il nodo"""
        self.running = False
        
        # Chiudi tutte le connessioni
        for conn in self.connections.values():
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except:
                pass
        self.connections.clear()
        
        # Chiudi server socket
        if self.client_socket_query:
            try:
                self.client_socket_query.shutdown(socket.SHUT_RDWR)  
                self.client_socket_query.close()
            except Exception as e:
                self.logger.debug(f"Errore chiusura Directory socket: {e}")
            finally:
                self.client_socket_query = None
                self.running = False

        if hasattr(self, 'client_thread_query') and self.client_thread_query.is_alive():
            self.logger.debug("Aspettando terminazione server thread...")
            self.client_thread_query.join(timeout=2.0)
        if self.client_thread_query.is_alive():
            self.logger.warning("Server thread non terminato entro timeout")
        
        self.logger.info("Nodo fermato")


    def _loop(self):
        """Loop principale del Directory - accetta connessioni"""
        while self.running:
            try:
                self.client_socket_query.settimeout(1.0)  # Timeout per permettere shutdown
                client_socket_reply, addr = self.client_socket_query.accept()
                
                # Gestisci connessione in thread separato
                client_thread_reply = threading.Thread(
                    target=self._handle_answer, 
                    args=(client_socket_reply, addr),
                    daemon=True
                )
                client_thread_reply.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Errore nel server loop: {e}")

    def _handle_answer(self, client_socket_reply: socket, addr: str):
        """Gestisce una connessione"""
        client_id = f"{addr[0]}:{addr[1]}"
        
        try:
            # Set timeout for client socket
            client_socket_reply.settimeout(10.0)
            
            # Ricevi dati
            data = client_socket_reply.recv(4096)
            if not data:
                self.logger.warning(f"Nessun dato ricevuto da {client_id}")
                return
                            
            payload_str = data.decode("utf-8")
            payload = json.loads(payload_str)

            match payload.get("cmd"):
                case "RETRIEVE":
                    response_data = self.create_nodes_packet()
                    client_socket_reply.sendall(response_data)

            client_socket_reply.shutdown(socket.SHUT_RDWR)
            client_socket_reply.close()
        
        except socket.timeout:
            self.logger.error(f"Timeout gestione client {client_id}")
        except Exception as e:
            self.logger.error(f"Errore gestione client {client_id}: {e}")
        finally:
            # Chiudi sempre la connessione
            try:
                client_socket_reply.shutdown(socket.SHUT_RDWR)
                client_socket_reply.close()
                self.logger.info(f"Connessione chiusa con {client_id}")
            except Exception as e:
                self.logger.debug(f"Errore chiusura connessione con {client_id}: {e}")
    


    def _make_network(self, num_guards=5, num_relays=5, num_exits=5, compromise_fraction=0.1) -> List[Node]:
        first_port = 20000
        # create guards
        for i in range(num_guards):
            compromised =True
            new_node = Node(f'G{i}', 'guard', compromise=compromised, ip_address=self._random_ipv4(),
                            band_width=self._random_band_width(), owner=self._random_owner(), port=first_port)

            self.guards.append(new_node)
            first_port+=1
        # relays
        for i in range(num_relays):
            compromised =True
            new_node = Node(f'R{i}', 'relay', compromise=compromised, ip_address=self._random_ipv4(),
                            band_width=self._random_band_width(), owner=self._random_owner(), port=first_port)

            self.relays.append(new_node)
            first_port+=1
        # exits
        for i in range(num_exits):
            compromised =True

            new_node = Node(f'E{i}', 'exit', compromise=compromised, ip_address=self._random_ipv4(),
                            band_width=self._random_band_width(), owner=self._random_owner(), port=first_port)

            self.exits.append(new_node)
            first_port+=1

    def create_nodes_packet(self) -> bytes:
        """
        Creates a pickle packet containing all guards, relays, and exits
        to be sent to clients requesting the network topology.

        Returns:
            bytes: Pickled bytes containing all network nodes
        """

        # Collect all nodes into a single list
        nodes = self.guards + self.relays + self.exits

        # Optional: You could keep only relevant attributes by creating a simplified dict
        # For full objects, just pickle the node instances
        packet = {
            "cmd": "RETRIEVED",
            "nodes": nodes  # Pickle can handle full Python objects
        }

        return pickle.dumps(packet)
    
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
import threading
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer, QObject, pyqtSignal
import sys
from Client import Client
from Server import Server
from Directory_Server import DirectoryServer
from Interface import DynamicNetworkEditor
from ClientTerminalWidget import TerminalWidget
from NodeTerminalWidget import NodeTerminal
from ServerTerminalWindow import ServerTerminal
import random
import time
from tor_security_sim import *

def random_ipv4() -> str:
    """Return a random IPv4 address."""
    a = random.randint(1, 254)
    b = random.randint(0, 255)
    c = random.randint(0, 255)
    d = random.randint(0, 255)
    return f"{a}.{b}.{c}.{d}"

class ConnectionWorker(QObject):
    connection_ready = pyqtSignal(list, str)  # path, color

    def __init__(self, client, circuit_id, color):
        super().__init__()
        self.client = client
        self.circuit_id = circuit_id
        self.color = color

    def connect(self, circuit_id):
        """Run connection in background thread"""
        if self.client.connect_to_tor_network(circuit_id=self.circuit_id):
            path = [
                self.client.id,
                self.client.get_guard(circuit_id).id,
                *[r.id for r in self.client.get_relays(circuit_id)],
                self.client.get_exit(circuit_id).id
            ]
            print(f"Connection established for {self.client.id}: {path}")
            self.connection_ready.emit(path, self.color)

class DestroyCircuitWorker(QObject):
    """Worker to destroy a Tor circuit asynchronously"""
    destroyed = pyqtSignal(str, int, list)  # client_id, circuit_id, path node_ids

    def __init__(self, client, circuit_id, client_id, path_node_ids):
        super().__init__()
        self.client = client
        self.circuit_id = circuit_id
        self.client_id = client_id
        self.path_node_ids = path_node_ids

    def run(self):
        try:
            # Destroy the circuit on the client
            self.client.destroy_circuit(self.circuit_id)
            print(f"Destroyed circuit {self.circuit_id} for client {self.client_id}")
            self.destroyed.emit(self.client_id, self.circuit_id, self.path_node_ids)
        except Exception as e:
            print(f"Error destroying circuit {self.circuit_id} for {self.client_id}: {e}")

class SendMessageWorker(QObject):
    # emit: exit_id, server_id, color, circuit_id, client_id
    message_sent = pyqtSignal(str, str, str, int, str)

    def __init__(self, client, server_ip, server_port, payload, circuit_id, color, server_id, exit_id, client_id):
        super().__init__()
        self.client = client
        self.server_ip = server_ip
        self.server_port = server_port
        self.payload = payload
        self.circuit_id = circuit_id
        self.color = color
        self.server_id = server_id
        self.exit_id = exit_id
        self.client_id = client_id
    def run(self):
        try:
            # circuit_path is now a list of Node objects
            circuit_nodes = self.client.circuits.get(self.circuit_id)
            if not circuit_nodes or not isinstance(circuit_nodes, list):
                print(f"Error: circuit {self.circuit_id} not ready on client {self.client_id}")
                return

            # Extract node IDs
            path_ids = [getattr(node, 'id', None) for node in circuit_nodes]
            if None in path_ids:
                print(f"Error: one or more nodes in circuit {self.circuit_id} have no id")
                return

            self.client.send_message_to_tor_network(
                self.server_ip,
                self.server_port,
                self.payload,
                self.circuit_id
            )

            # emit with circuit_id and client_id
            if self.exit_id and self.server_id:
                self.message_sent.emit(
                    self.exit_id,
                    self.server_id,
                    self.color,
                    self.circuit_id,
                    self.client_id
                )
        except Exception as e:
            print(f"Error in SendMessageWorker: {e}")

class EntityConnectionManager:
    """Manages client connections and their workers"""
    def __init__(self, editor):
        self.editor = editor
        self.clients = {}
        self.terminals = {}
        self.servers = {}
        self.edge_usage = {}
        self.workers = []
        self.colors = ['#e74c3c', '#3498db', '#2ecc71', '#f1c40f', '#9b59b6', '#1abc9c']
        self.color_index = 0
        self.connected_clients = set()
        self._lock = threading.Lock()  # protect shared state (edge_usage, clients)
    
    def register_client(self, client_id, client, analyzer, circuit_id):
        """Register a client and a new circuit"""
        if client_id not in self.clients:
            self.clients[client_id] = {
                'client': client,
                'circuits': {}  # key: circuit_id -> value: {'color': str, 'connected': bool}
            }

        color = self.colors[self.color_index % len(self.colors)]
        self.color_index += 1

        self.clients[client_id]['circuits'][circuit_id] = {
            'color': color,
            'connected': False
        }

        # Terminal for client
        if client_id not in self.terminals:
            terminal = TerminalWidget(client_id, client, analyzer, manager=self, editor=self.editor)
            self.terminals[client_id] = terminal

        client.manager = self

    def register_node(self, node, dir_server):
        """Register server/relay/guard/exit node with log terminal.
        node_type: 'guard', 'relay', 'exit', etc. If 'exit', the NodeTerminal
        will allow commands (e.g. redirect).
        """
        terminal = NodeTerminal(node, dir_server)
        self.terminals[node.id] = terminal
       

    def register_server(self, server_id, server):
        self.servers[server_id] = {
            'server': server,
            'server_id': server_id,
        }

        terminal = ServerTerminal(server_id, server)
        self.terminals[server_id] = terminal
        self.servers[server_id]['server'].manager = self

    
    def on_client_click(self, client_id):
        """Handle client node click - show terminal"""
        if client_id not in self.terminals:
            print(f"Terminal for {client_id} not found")
            return
        
        terminal = self.terminals[client_id]
        terminal.show()
        terminal.raise_()
        terminal.activateWindow()

        # If already connected, tell the user in the terminal
        if client_id in self.connected_clients:
            terminal.append_log(f"Client {client_id} is already connected")
            return
        
    def on_node_click(self, node_id):
        """Show terminal for nodes"""
        if node_id not in self.terminals:
            print(f"Terminal for {node_id} not found")
            return
        terminal = self.terminals[node_id]
        terminal.show()
        terminal.raise_()
        terminal.activateWindow()
        
        terminal = self.terminals[node_id]
        
        # Show terminal
        terminal.show()
        terminal.raise_()
        terminal.activateWindow()
        
        # Check if already connected
        if node_id in self.connected_clients:
            terminal.append_log(f"Node {node_id} is already connected")
            return
        
    def on_server_click(self, server_id):
        """Show terminal for servers"""
        if server_id not in self.terminals:
            print(f"Terminal for {server_id} not found")
            return
        terminal = self.terminals[server_id]
        terminal.show()
        terminal.raise_()
        terminal.activateWindow()
        
        terminal = self.terminals[server_id]
        
        # Show terminal
        terminal.show()
        terminal.raise_()
        terminal.activateWindow()
        
        # Check if already connected
        if server_id in self.connected_clients:
            terminal.append_log(f"Server {server_id} is already connected")
            return
    
    def connect_client(self, client_id, circuit_id):
        client_info = self.clients[client_id]
        circuit_info = client_info['circuits'][circuit_id]
        

        worker = ConnectionWorker(client_info['client'], circuit_id, circuit_info['color'])

        def on_connected(path, color):
            # store path and edges
            circuit_info['path'] = path
            edges = [(path[i], path[i+1]) for i in range(len(path)-1)]
            circuit_info['edges'] = edges
            circuit_info['exit_id'] = path[-1]  # last node is the exit

            # increment shared edge usage and draw
            with self._lock:
                for edge in edges:
                    self.edge_usage[edge] = self.edge_usage.get(edge, 0) + 1
                    print(f"[DEBUG] Increment: Edge {edge} now has usage {self.edge_usage[edge]} (after connect {circuit_id})")
                unique_circuit_id = f"{client_id}_{circuit_id}"
                self.editor.circuits[unique_circuit_id] = path
                self.editor.draw_circuit(unique_circuit_id, color)
                circuit_info['unique_circuit_id'] = unique_circuit_id
            # now that the path is fully known, mark connected
            circuit_info['connected'] = True

        worker.connection_ready.connect(on_connected)

        self.workers.append(worker)
        threading.Thread(
            target=worker.connect,
            args=(circuit_id,),  
            daemon=True
        ).start()

    def destroy_client_circuit(self, client_id, circuit_id):
        if client_id not in self.clients:
            print(f"Client {client_id} not found")
            return

        circuit_info = self.clients[client_id]['circuits'].get(circuit_id)
        if not circuit_info:
            print(f"Circuit {circuit_id} not found for client {client_id}")
            return

        client = self.clients[client_id]['client']
        # capture manager-side data now
        path = circuit_info.get('path', [])  # used for worker
        edges = circuit_info.get('edges', []).copy() if 'edges' in circuit_info else []
        exit_server_edges = circuit_info.get('exit_server_edges', []).copy() if 'exit_server_edges' in circuit_info else []

        # reduce edge_usage for the Tor-path edges immediately (so other circuits keep valid counts)
        with self._lock:
            for edge in edges:
                if edge in self.edge_usage:
                    self.edge_usage[edge] -= 1
                    print(f"[DEBUG] Decrement: Edge {edge} now has usage {self.edge_usage.get(edge, 0)} (during destroy {circuit_id})")
                    if self.edge_usage[edge] <= 0:
                        del self.edge_usage[edge]
                        unique_circuit_id = circuit_info.get('unique_circuit_id', f"{client_id}_{circuit_id}")
                        self.editor.remove_circuit(unique_circuit_id)

            # reduce edge_usage for exit->server edges immediately
            for edge in exit_server_edges:
                if edge in self.edge_usage:
                    self.edge_usage[edge] -= 1
                    print(f"[DEBUG] Decrement: Exit->Server edge {edge} now has usage {self.edge_usage.get(edge, 0)} (during destroy {circuit_id})")
                    if self.edge_usage[edge] <= 0:
                        del self.edge_usage[edge]
                        self.editor.remove_circuit(f"{client_id}_{circuit_id}_exit") 

            # reduce edge_usage for exit->server edges immediately
            for edge in exit_server_edges:
                if edge in self.edge_usage:
                    self.edge_usage[edge] -= 1
                    print(f"[DEBUG] Decrement: Exit->Server edge {edge} now has usage {self.edge_usage.get(edge, 0)} (during destroy {circuit_id})")
                    if self.edge_usage[edge] <= 0:
                        del self.edge_usage[edge]
                        unique_circuit_id = circuit_info.get('unique_circuit_id', f"{client_id}_{circuit_id}")
                        self.editor.remove_circuit(unique_circuit_id)

            # **Important:** remove the manager-side circuit record now so the later
            # on_circuit_destroyed handler doesn't double-decrement the same edges.
            try:
                del self.clients[client_id]['circuits'][circuit_id]
                print(f"Circuit {circuit_id} removed from manager records (pending client-side teardown)")
            except Exception:
                # if deletion fails, ignore (we'll still start worker)
                pass

        # Now call the client teardown in background. Manager record already cleaned.
        worker = DestroyCircuitWorker(client, circuit_id, client_id, path)
        worker.destroyed.connect(self.on_circuit_destroyed)
        self.workers.append(worker)
        threading.Thread(target=worker.run, daemon=True).start()


    def on_circuit_destroyed(self, client_id, circuit_id, path_node_ids):
        client_circuits = self.clients.get(client_id, {}).get('circuits', {})
        circuit_info = client_circuits.get(circuit_id)

        if not circuit_info:
            # Manager already removed the circuit during destroy_client_circuit.
            print(f"Circuit {circuit_id} cleanup: manager had no record (client-side may have removed).")
            return

        # If somehow manager still has record, do a final safe decrement (double-check)
        with self._lock:
            for edge in circuit_info.get('edges', []):
                if edge in self.edge_usage:
                    self.edge_usage[edge] -= 1
                    print(f"[DEBUG] Decrement: Edge {edge} now has usage {self.edge_usage[edge]} (after destroy {circuit_id})")

                    if self.edge_usage[edge] <= 0:
                        del self.edge_usage[edge]
                        print(f"[DEBUG] Removing edge {edge} from GUI (no circuits left)")
                        self.editor.remove_connection_path(list(edge))

            for edge in circuit_info.get('exit_server_edges', []):
                if edge in self.edge_usage:
                    self.edge_usage[edge] -= 1
                    if self.edge_usage[edge] <= 0:
                        del self.edge_usage[edge]
                        self.editor.remove_connection_path(list(edge))

            # finally delete the circuit record
            try:
                del self.clients[client_id]['circuits'][circuit_id]
            except Exception:
                pass

            print(f"Circuit {circuit_id} removed from client {client_id} records and connection cleared")

    def send_message(self, client_id, server_ip, server_port, payload, circuit_id):
        """Send message via a specific circuit of a client"""
        client_info = self.clients.get(client_id)
        if not client_info:
            print(f"Client {client_id} not registered")
            return

        circ = client_info['circuits'].get(circuit_id)
        if not circ or not circ.get('connected'):
            print(f"Circuit {circuit_id} not ready for {client_id}")
            return

        # find server ID
        server_id = None
        for sid, info in self.servers.items():
            server = info['server']
            if server.ip == server_ip and server.port == server_port:
                server_id = sid
                break
        if not server_id:
            print(f"No server found with IP {server_ip} and port {server_port}")
            return

        circuit = self.clients[client_id]['circuits'][circuit_id]

        if not circuit.get('connected') or 'path' not in circuit:
            print(f"Circuit {circuit_id} is not ready for sending")
            return

        exit_id = circuit['path'][-1]  # The last node in the circuit path
        worker = SendMessageWorker(
            client=self.clients[client_id]['client'],  # use 'client', not 'client_obj'
            server_ip=server_ip,
            server_port=server_port,
            payload=payload,
            circuit_id=circuit_id,
            color=circuit['color'],
            server_id=server_id,
            exit_id=exit_id,
            client_id=client_id
        )

        # Connect signal to updated _draw_exit_to_server
        worker.message_sent.connect(self._draw_exit_to_server)
        self.workers.append(worker)
        threading.Thread(target=worker.run, daemon=True).start()
        
    def _draw_exit_to_server(self, exit_id, server_id, color, circuit_id, client_id):
        """Draw exit->server edge and track usage per circuit using DynamicNetworkEditor's draw_circuit."""
        
        # Verifica che i nodi esistano
        if exit_id not in self.editor.nodes:
            print(f"[DEBUG] Exit node {exit_id} not in editor.nodes, skipping draw")
            return
        if server_id not in self.editor.nodes:
            print(f"[DEBUG] Server node {server_id} not in editor.nodes, skipping draw")
            return

        client_info = self.clients.get(client_id)
        if not client_info:
            return

        circ = client_info['circuits'].get(circuit_id)
        if not circ:
            return

        circ.setdefault('exit_server_edges', [])

        # Tratta l'edge come un mini-circuito separato
        edge_circuit_id = f"{client_id}_{circuit_id}_exit"
        circ['exit_server_edges'].append((exit_id, server_id))
        self.edge_usage[(exit_id, server_id)] = self.edge_usage.get((exit_id, server_id), 0) + 1
        print(f"[DEBUG] Increment: Exit->Server edge ({exit_id}, {server_id}) usage now {self.edge_usage[(exit_id, server_id)]} (circuit {circuit_id})")

        # Disegna usando draw_circuit
        self.editor.circuits[edge_circuit_id] = [exit_id, server_id]
        self.editor.draw_circuit(edge_circuit_id, color)

    
    def add_circuit(self, client_id, circuit_id):
        """Add a new circuit to an existing client"""
        if client_id not in self.clients:
            print(f"Client {client_id} not registered")
            return

        client_info = self.clients[client_id]

        if circuit_id in client_info['circuits']:
            print(f"Circuit {circuit_id} already exists for {client_id}")
            return

        color = self.colors[self.color_index % len(self.colors)]
        self.color_index += 1

        client_info['circuits'][circuit_id] = {
            'color': color,
            'connected': False
        }

        print(f"Added circuit {circuit_id} for client {client_id} with color {color}")

    def get_circuit_path(self, client_id, circuit_id):
        client_info = self.clients.get(client_id)
        if not client_info:
            return []
        # Store the connection path when connecting
        circuit_info = client_info['circuits'].get(circuit_id)
        if not circuit_info:
            return []
        return circuit_info.get('path', [])

def main():
    dir_server= DirectoryServer(random_ipv4(),9000)

    nodes = dir_server.guards+dir_server.relays+dir_server.exits

    provider_server_1 = Server("S1", random_ipv4(), 21000, compromised=False)
    provider_server_2 = Server("S2", random_ipv4(), 27000, compromised=False)
    attacker_server = Server("S3", random_ipv4(), 28000, compromised=True)

    # Initialize clients
    client_1 = Client("C1", random_ipv4(), 22000, 22001, nodes)
    client_2 = Client("C2", random_ipv4(), 43000, 43001, nodes)

    # Start servers in background threads
    threading.Thread(target=provider_server_1.start, daemon=True).start()
    threading.Thread(target=provider_server_2.start, daemon=True).start()
    threading.Thread(target=attacker_server.start, daemon=True).start()

    # Start nodes
    for node in dir_server.guards + dir_server.relays + dir_server.exits:
        threading.Thread(target=node.start, daemon=True).start()


    # Setup GUI nodes - use actual node IDs from directory server
    hosts = [{'id': 'C1'}, {'id': 'C2'}]
    guards = [{'id': node.id} for node in dir_server.guards]
    relays = [{'id': node.id} for node in dir_server.relays]
    exits = [{'id': node.id} for node in dir_server.exits]
    servers = [{'id': 'S1'}, {'id': 'S2'}, {'id': 'S3'}]

    app = QApplication(sys.argv)
    editor = DynamicNetworkEditor(hosts=hosts, guards=guards, relays=relays, exits=exits, servers=servers)
    editor.setWindowTitle("Dynamic Network Editor - Click on clients to open terminal")
    editor.resize(1400, 800)

    compromised_nodes_ids = [
        node.id for group in (dir_server.guards, dir_server.exits, dir_server.relays)
        for node in group if node.compromised
    ]

    compromised_nodes = [
        node for group in (dir_server.guards, dir_server.exits, dir_server.relays)
        for node in group if node.compromised
    ]

    analyzer = CorrelationAttackAnalyzer(
                    compromised_nodes=compromised_nodes,
                    time_window=10.0,
                    correlation_threshold=0.75
                )

    compromised_nodes_ids.append("S3")

    editor.highlight_nodes(compromised_nodes_ids)

    editor.show()

    # Create connection manager
    manager = EntityConnectionManager(editor)

    # Register servers
    manager.register_server('S1', provider_server_1)
    manager.register_server('S2', provider_server_2)
    manager.register_server('S3', attacker_server)

    editor.set_node_clickable('S1', manager.on_server_click)
    editor.set_node_clickable('S2', manager.on_server_click)
    editor.set_node_clickable('S3', manager.on_server_click)
    
    # Register clients
    manager.register_client('C1', client_1, analyzer, circuit_id=1)
    manager.register_client('C2', client_2, analyzer, circuit_id=2)
    
    # Make client nodes clickable to open terminal
    editor.set_node_clickable('C1', manager.on_client_click)
    editor.set_node_clickable('C2', manager.on_client_click)

    for guard in dir_server.guards:
        manager.register_node(guard, dir_server)
        editor.set_node_clickable(guard.id, manager.on_node_click)

    for relay in dir_server.relays:
        manager.register_node(relay, dir_server)
        editor.set_node_clickable(relay.id, manager.on_node_click)

    for exit in dir_server.exits:
        manager.register_node(exit, dir_server)
        editor.set_node_clickable(exit.id, manager.on_node_click)


    # Graceful shutdown when GUI closes
    def cleanup():
        clients = [client_1, client_2]
        
        # Close all terminals
        for terminal in manager.terminals.values():
            terminal.close()
        
        for client in clients:
            try:
                for key in list(client.circuits.keys()):
                    for node in client.circuits.get(key):
                        node.stop()
            except (AttributeError, Exception):
                pass
        
        provider_server_1.stop()
        provider_server_2.stop()
        dir_server.stop()
        print("Simulation terminated.")

    app.aboutToQuit.connect(cleanup)
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
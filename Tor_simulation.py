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

def random_ipv4() -> str:
    """Return a random IPv4 address."""
    a = random.randint(1, 254)
    b = random.randint(0, 255)
    c = random.randint(0, 255)
    d = random.randint(0, 255)
    return f"{a}.{b}.{c}.{d}"

class ConnectionWorker(QObject):
    """Worker to handle connection in background thread with Qt signals"""
    connection_ready = pyqtSignal(list, str)
    
    def __init__(self, client, circuit_id, color):
        super().__init__()
        self.client = client
        self.circuit_id = circuit_id
        self.color = color
    
    def connect(self):
        """Run connection in background thread"""
        if self.client.connect_to_tor_network(circuit_id=self.circuit_id):
            connection = [
                self.client.id,
                self.client.guard_chosen.id,
                *[r.id for r in self.client.relays_chosen],
                self.client.exit_chosen.id,
            ]
            print(f"Connection established for {self.client.id}: {connection}")
            self.connection_ready.emit(connection, self.color)

class SendMessageWorker(QObject):
    """Worker to send a message via Tor circuit"""
    message_sent = pyqtSignal(str, str, str)  # exit_id, server_id, color

    def __init__(self, client, server_ip, server_port, payload, circuit_id, color, server_id):
        super().__init__()
        self.client = client
        self.server_ip = server_ip
        self.server_port = server_port
        self.payload = payload
        self.circuit_id = circuit_id
        self.color = color
        self.server_id = server_id

    def run(self):
        try:
            self.client.send_message_to_tor_network(
                self.server_ip,
                self.server_port,
                self.payload,
                self.circuit_id
            )
            
            exit_id = self.client.exit_chosen.id if self.client.exit_chosen else None
            if exit_id and self.server_id:
                self.message_sent.emit(exit_id, self.server_id, self.color)
        except Exception as e:
            print(f"Error in SendMessageWorker: {e}")

class EntityConnectionManager:
    """Manages client connections and their workers"""
    def __init__(self, editor):
        self.editor = editor
        self.clients = {}
        self.terminals = {}
        self.servers = {}
        self.workers = []
        self.colors = ['#e74c3c', '#3498db', '#2ecc71', '#f1c40f', '#9b59b6', '#1abc9c']
        self.color_index = 0
        self.connected_clients = set()
    
    def register_client(self, client_id, client, circuit_id):
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
            terminal = TerminalWidget(client_id, client)
            self.terminals[client_id] = terminal

        client.manager = self

    def register_node(self, node_id, node):
        """Register server/relay/guard/exit node with log terminal"""
        terminal = NodeTerminal(node_id, node.logger)
        self.terminals[node_id] = terminal

    def register_server(self, server_id, server):
        self.servers[server_id] = {
            'server': server,
            'server_id': server_id,
        }

        terminal = TerminalWidget(server_id, server)
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
        """Connect a specific circuit of a client"""
        if client_id not in self.clients:
            print(f"Client {client_id} not registered")
            return

        client_info = self.clients[client_id]
        if circuit_id not in client_info['circuits']:
            print(f"Circuit {circuit_id} not registered for {client_id}")
            return

        circuit_info = client_info['circuits'][circuit_id]
        if circuit_info['connected']:
            print(f"Circuit {circuit_id} of {client_id} already connected")
            return

        print(f"Initiating connection for {client_id}, circuit {circuit_id}...")

        # Start worker
        worker = ConnectionWorker(
            client_info['client'],
            circuit_id,
            circuit_info['color']
        )
        worker.connection_ready.connect(self.editor.draw_connection_path)
        self.workers.append(worker)
        threading.Thread(target=worker.connect, daemon=True).start()

        # Mark circuit as connected
        circuit_info['connected'] = True

    def send_message(self, client_id, server_ip, server_port, payload, circuit_id):
        """Send message via a specific circuit of a client"""
        if client_id not in self.clients:
            print(f"Client {client_id} not registered")
            return

        client_info = self.clients[client_id]

        if circuit_id not in client_info['circuits']:
            print(f"Circuit {circuit_id} not registered for {client_id}")
            return

        # Find server ID by IP/port
        server_id = None
        for sid, info in self.servers.items():
            server = info['server']
            if server.ip == server_ip and server.port == server_port:
                server_id = sid
                break

        if not server_id:
            print(f"No server found with IP {server_ip} and port {server_port}")
            return

        color = client_info['circuits'][circuit_id]['color']

        worker = SendMessageWorker(
            client_info['client'],
            server_ip,
            server_port,
            payload,
            circuit_id,
            color,
            server_id
        )
        worker.message_sent.connect(self._draw_exit_to_server)
        self.workers.append(worker)
        threading.Thread(target=worker.run, daemon=True).start()

    def _draw_exit_to_server(self, exit_id, server_id, color):
        """Draw line from exit node to server"""
        if exit_id in self.editor.nodes and server_id in self.editor.nodes:
            self.editor.draw_connection_path([exit_id, server_id], color)
    
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

def main():
    # Initialize servers
    dir_server = DirectoryServer(random_ipv4(), 9000)
    provider_server_1 = Server("S1", random_ipv4(), 21000)
    provider_server_2 = Server("S2", random_ipv4(), 27000)

    # Initialize clients
    client_1 = Client("C1", random_ipv4(), 22000, 22001)
    client_2 = Client("C2", random_ipv4(), 43000, 43001)

    # Start servers in background threads
    threading.Thread(target=dir_server.start, daemon=True).start()
    threading.Thread(target=provider_server_1.start, daemon=True).start()
    threading.Thread(target=provider_server_2.start, daemon=True).start()

    # Setup GUI nodes - use actual node IDs from directory server
    hosts = [{'id': 'C1'}, {'id': 'C2'}]
    guards = [{'id': node.id} for node in dir_server.guards]
    relays = [{'id': node.id} for node in dir_server.relays]
    exits = [{'id': node.id} for node in dir_server.exits]
    servers = [{'id': 'S1'}, {'id': 'S2'}]

    app = QApplication(sys.argv)
    editor = DynamicNetworkEditor(hosts=hosts, guards=guards, relays=relays, exits=exits, servers=servers)
    editor.setWindowTitle("Dynamic Network Editor - Click on clients to open terminal")
    editor.resize(1400, 800)
    editor.show()

    # Create connection manager
    manager = EntityConnectionManager(editor)

    # Register servers
    manager.register_server('S1', provider_server_1)
    manager.register_server('S2', provider_server_2)

    editor.set_node_clickable('S1', manager.on_client_click)
    editor.set_node_clickable('S2', manager.on_client_click)
    
    # Register clients
    manager.register_client('C1', client_1, circuit_id=1)
    manager.register_client('C2', client_2, circuit_id=2)
    
    # Make client nodes clickable to open terminal
    editor.set_node_clickable('C1', manager.on_client_click)
    editor.set_node_clickable('C2', manager.on_client_click)

    for guard in dir_server.guards:
        manager.register_node(guard.id, guard)
        editor.set_node_clickable(guard.id, manager.on_node_click)

    for relay in dir_server.relays:
        manager.register_node(relay.id, relay)
        editor.set_node_clickable(relay.id, manager.on_node_click)

    for exit_node in dir_server.exits:
        manager.register_node(exit_node.id, exit_node)
        editor.set_node_clickable(exit_node.id, manager.on_node_click)
    
    def setup_terminal_connect(client_id):
        """Enhance terminal to support multiple circuits dynamically"""
        terminal = manager.terminals[client_id]
        original_process = terminal.process_command

        def enhanced_process():
            input_text = terminal.input.text().strip()
            terminal.input.clear()
            if not input_text:
                return

            parts = input_text.split()
            command = parts[0].lower()
            args = parts[1:]

            print(f"DEBUG: Processing command '{input_text}' for {client_id}")

            if command == "connect":
                if len(args) != 1:
                    terminal.append_log("ERROR: 'connect' command requires exactly 1 argument (circuit id).")
                    return
                try:
                    circuit_id = int(args[0])
                except ValueError:
                    terminal.append_log("ERROR: Circuit ID must be an integer")
                    return

                if circuit_id not in manager.clients[client_id]['circuits']:
                    manager.add_circuit(client_id, circuit_id)

                circuit_info = manager.clients[client_id]['circuits'][circuit_id]
                if circuit_info['connected']:
                    terminal.append_log(f"Circuit {circuit_id} is already connected")
                    return

                terminal.append_log(f"Scheduling connection for circuit {circuit_id}...")
                QTimer.singleShot(
                    100,
                    lambda cid=client_id, circ=circuit_id: manager.connect_client(cid, circ)
                )

            elif command == "send":
                if len(args) < 4:
                    terminal.append_log("Usage: send <server_ip> <server_port> <message> <circuit_id>")
                    return

                server_ip = args[0]
                try:
                    server_port = int(args[1])
                    circuit_id = int(args[-1])
                except ValueError:
                    terminal.append_log("Error: port and circuit_id must be integers")
                    return

                payload = " ".join(args[2:-1])

                # Add circuit dynamically if missing
                if circuit_id not in manager.clients[client_id]['circuits']:
                    manager.add_circuit(client_id, circuit_id)

                manager.send_message(client_id, server_ip, server_port, payload, circuit_id)
                terminal.append_log(f"Sending '{payload}' to {server_ip}:{server_port} via circuit {circuit_id}")

            else:
                # fallback to original behavior
                original_process()

        # Replace terminal's process_command and reconnect signal
        terminal.process_command = enhanced_process
        try:
            terminal.input.returnPressed.disconnect()
        except Exception:
            pass
        terminal.input.returnPressed.connect(terminal.process_command)


    # Setup terminals for all clients dynamically
    for client_id in manager.clients.keys():
        setup_terminal_connect(client_id)

    # Graceful shutdown when GUI closes
    def cleanup():
        clients = [client_1, client_2]
        
        # Close all terminals
        for terminal in manager.terminals.values():
            terminal.close()
        
        for client in clients:
            try:
                if client.guard_chosen:
                    client.guard_chosen.stop()
                if client.relays_chosen:
                    for node in client.relays_chosen:
                        node.stop()
                if client.exit_chosen:
                    client.exit_chosen.stop()
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
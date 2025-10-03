from Client import Client
from Node import Node
from Server import Server
from Directory_Server import DirectoryServer
from typing import List
import random
import time

def random_ipv4() -> str:
        """Ritorna una stringa IPv4 casuale."""
        a = random.randint(1, 254)   # evitiamo 0 e 255 nel primo ottetto
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(0, 255)
        return f"{a}.{b}.{c}.{d}"


def main():
    dir_server= DirectoryServer(random_ipv4(),9000)

    dir_server.start()

    provider_server_1 = Server("S1", random_ipv4(), 21000)
    provider_server_1.start()

    provider_server_2 = Server("S2", random_ipv4(), 27000)
    provider_server_2.start()

    client_1 = Client("C1", random_ipv4(), 22000, 22001)
    client_2 = Client("C2", random_ipv4(), 22000, 22001)

    #client_2 = Client("C2", random_ipv4(), 43000, 43001)

    circuit1 = client_1.connect_to_tor_network(circuit_id = 1)
    circuit2 = client_2.connect_to_tor_network(circuit_id = 1)

    client_1.send_message_to_tor_network(provider_server_1.ip, provider_server_1.port, "alpha", circuit_id=1)
    client_2.send_message_to_tor_network(provider_server_1.ip, provider_server_1.port, "alpha", circuit_id=1)
    client_1.destroy_circuit(1)
    client_2.send_message_to_tor_network(provider_server_1.ip, provider_server_1.port, "alpha", circuit_id=1)
    circuit1 = client_1.connect_to_tor_network(circuit_id = 1)
    client_1.send_message_to_tor_network(provider_server_1.ip, provider_server_1.port, "alpha", circuit_id=1)

    #circuit2 = client_2.connect_to_tor_network(circuit_id = 2)
    """if circuit1 and circuit2:
        client_1.send_message_to_tor_network(provider_server_1.ip, provider_server_1.port, "alpha", circuit_id=1)
        client_2.send_message_to_tor_network(provider_server_1.ip, provider_server_1.port, "alpha", circuit_id=2)
        done = client_1.destroy_circuit(1)
        if done:
            client_2.send_message_to_tor_network(provider_server_1.ip, provider_server_1.port, "alpha", circuit_id=2)"""



        

       

    #if client_2.connect_to_tor_network(circuit_id = 1):
    #   client_2.send_message_to_tor_network(provider_server_2.ip, provider_server_2.port, "beta", circuit_id=1)
    #   for node in client_1.nodes:
    #        if node.running:
    #            interesting_nodes.append(node)


    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client_1.guard_chosen.stop()
        
        for node in client_1.relays_chosen:
            node.stop()

        client_1.exit_chosen.stop()

        provider_server_1.stop()
        dir_server.stop()

        print("Simulazione terminata")

    

if __name__ == "__main__":
    main()
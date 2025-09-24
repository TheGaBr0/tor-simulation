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

    client_1 = Client("C1", random_ipv4(), 22000, 22001)

    client_1.connect_to_tor_network()



    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client_1.guard_chosen.stop()
        client_1.relay_chosen.stop()
        client_1.exit_chosen.stop()

        provider_server_1.stop()
        dir_server.stop()

        print("Simulazione terminata")

    

if __name__ == "__main__":
    main()
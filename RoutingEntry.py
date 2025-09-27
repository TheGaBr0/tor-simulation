class RoutingEntry:
    def __init__(self, source_ip: str, source_port: int, circuit_id: int, session_key):
        self.source_coords = (source_ip, source_port)
        self._circuit_id = circuit_id
        self._session_key = session_key
        self.dest_coords = (None, None)

    # Getters
    def get_source_coords(self) -> tuple[str, int]:
        return self.source_coords

    def get_circuit_id(self) -> int:
        return self._circuit_id

    def get_session_key(self) -> int:
        return self._session_key

    def get_dest_coords(self) -> tuple[str,int]:
        return self.dest_coords

    # Setters

    def set_session_key(self, session_key: int):
        self._session_key = session_key

    def set_dest_coords(self, dest_ip: str, dest_port: int):
        self.dest_coords = (dest_ip, dest_port)

    def __str__(self):
        return (f"RoutingEntry(src={self.source_coords}, dest={self.dest_coords}, "
                f"circ_id={self._circuit_id}, session_key={self._session_key})")

    def __repr__(self):
        return self.__str__()
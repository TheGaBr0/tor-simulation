class RoutingEntry:
    def __init__(self, source_ip: str, source_port: int,
                 in_circ_id: int, out_circ_id: int, session_key: int, created_at: int):
        self.source_coords = (source_ip, source_port)
        self.in_circ_id = in_circ_id         
        self.out_circ_id = out_circ_id             
        self._session_key = session_key
        self.dest_coords = (None, None) 
        self.created_at = created_at

    # Getters
    def get_source_coords(self): return self.source_coords
    def get_in_circ_id(self): return self.in_circ_id
    def get_out_circ_id(self): return self.out_circ_id
    def get_session_key(self): return self._session_key
    def get_dest_coords(self): return self.dest_coords
    def get_creation_timestamp(self): return self.created_at

    # Setters

    def set_session_key(self, session_key): self._session_key = session_key
    def set_dest_coords(self, dest_ip, dest_port): self.dest_coords = (dest_ip, dest_port)

    def __str__(self):
        return (f"RoutingEntry(src={self.source_coords}, dest={self.dest_coords}, "
                f"in_circ_id={self.in_circ_id}, out_circ_id={self.out_circ_id}, "
                f"session_key={self._session_key})")
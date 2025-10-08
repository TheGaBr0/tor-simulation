class Oracle:
    def __init__(self):
        self.symb_ip_map = {}
    
    def add_symb_ip(self, symb_ip, port):
        self.symb_ip_map[port] = symb_ip

    def del_symb_ip(self, port):
        self.symb_ip_map.pop(port)

    def get_symb_ip(self, port):
        return self.symb_ip_map.get(port)
    

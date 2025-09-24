import base64

class TorMessage:
    """Rappresenta un messaggio nella rete Tor"""
    def __init__(self, CircID: str, cmd: str, payload: bytes):
        self.payload = payload
        self.circ_id = CircID
        self.cmd= cmd
    
    
    def to_dict(self):
        return {
            "circ_id": self.circ_id,
            "cmd": self.cmd,
            "payload": base64.b64encode(self.payload).decode('utf-8')  # rappresentazione esadecimale
        }

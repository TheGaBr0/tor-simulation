import struct
from typing import Union, Optional, List

class TorCommands:
    CREATE = 0
    CREATED = 1
    RELAY = 2

class RelayCommands:
    EXTEND = 0
    EXTENDED = 1


class TorCell:
    """
    Classe per gestire le celle del protocollo Tor.
    Supporta sia celle standard che celle relay.
    """
    
    # Dimensioni fisse dei campi (in bytes)
    CIRCID_SIZE = 2
    CMD_SIZE = 1
    RELAY_SIZE = 1
    STREAMID_SIZE = 2
    DIGEST_SIZE = 6
    LEN_SIZE = 2
    DATA_SIZE = 498  # Per celle relay
    STANDARD_DATA_SIZE = 509  # Per celle standard
    
    # Dimensioni totali
    STANDARD_CELL_SIZE = CIRCID_SIZE + CMD_SIZE + STANDARD_DATA_SIZE  # 512 bytes
    RELAY_CELL_SIZE = CIRCID_SIZE + CMD_SIZE + RELAY_SIZE + STREAMID_SIZE + DIGEST_SIZE + LEN_SIZE + DATA_SIZE  # 512 bytes
    
    def __init__(self, circid: int, cmd: int, data: bytes = b'', 
                 is_relay: bool = False, relay: int = 0, streamid: int = 0, 
                 digest: bytes = b'', length: int = 0):
        """
        Inizializza una cella Tor.
        
        Args:
            circid: Circuit ID (2 bytes)
            cmd: Command (1 byte)
            data: Dati della cella
            is_relay: Se True, crea una cella relay
            relay: Relay command (1 byte, solo per celle relay)
            streamid: Stream ID (2 bytes, solo per celle relay)
            digest: Digest (6 bytes, solo per celle relay)
            length: Lunghezza dei dati (2 bytes, solo per celle relay)
        """
        self.circid = circid
        self.cmd = cmd
        self.is_relay = is_relay
        
        if is_relay:
            self.relay = relay
            self.streamid = streamid
            self.digest = digest if digest else b'\x00' * self.DIGEST_SIZE
            self.length = length if length > 0 else len(data)
            # Assicura che i dati non superino la dimensione massima
            self.data = data[:self.DATA_SIZE] if data else b''
            # Padding dei dati se necessario
            self.data = self.data.ljust(self.DATA_SIZE, b'\x00')
        else:
            # Cella standard
            self.data = data[:self.STANDARD_DATA_SIZE] if data else b''
            # Padding dei dati se necessario
            self.data = self.data.ljust(self.STANDARD_DATA_SIZE, b'\x00')
    
    def to_bytes(self) -> bytes:
        """
        Converte la cella in bytes per l'invio.
        
        Returns:
            bytes: Rappresentazione binaria della cella
        """
        if self.is_relay:
            # Formato: CircID(2) + CMD(1) + Relay(1) + StreamID(2) + Digest(6) + Len(2) + DATA(498)
            return struct.pack(
                '>HB B H 6s H 498s',
                self.circid,
                self.cmd,
                self.relay,
                self.streamid,
                self.digest[:self.DIGEST_SIZE],
                self.length,
                self.data
            )
        else:
            # Formato: CircID(2) + CMD(1) + DATA(509)
            return struct.pack(
                '>HB 509s',
                self.circid,
                self.cmd,
                self.data
            )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'TorCell':
        """
        Crea una cella Tor da bytes.
        
        Args:
            data: Dati binari della cella
            
        Returns:
            TorCell: Istanza della cella
            
        Raises:
            ValueError: Se i dati non hanno la dimensione corretta
        """
        if len(data) != 512:
            raise ValueError(f"I dati devono essere esattamente 512 bytes, ricevuti {len(data)}")
        
        # Leggi i primi 3 bytes per determinare il tipo
        circid, cmd = struct.unpack('>HB', data[:3])
        
        # Determina se è una cella relay controllando il comando
        # I comandi relay sono tipicamente RELAY (3) o RELAY_EARLY (9)
        is_relay_cmd = cmd in [3, 9]  # RELAY, RELAY_EARLY
        
        if is_relay_cmd:
            # Parsing come cella relay
            unpacked = struct.unpack('>HB B H 6s H 498s', data)
            return cls(
                circid=unpacked[0],
                cmd=unpacked[1],
                is_relay=True,
                relay=unpacked[2],
                streamid=unpacked[3],
                digest=unpacked[4],
                length=unpacked[5],
                data=unpacked[6]
            )
        else:
            # Parsing come cella standard
            unpacked = struct.unpack('>HB 509s', data)
            return cls(
                circid=unpacked[0],
                cmd=unpacked[1],
                is_relay=False,
                data=unpacked[2]
            )
    
    # Proprietà per accesso statico ai campi
    @property
    def circuit_id(self) -> int:
        """Circuit ID (2 bytes)"""
        return self.circid
    
    @property
    def command(self) -> int:
        """Command (1 byte)"""
        return self.cmd
    
    @property
    def relay_command(self) -> Optional[int]:
        """Relay command (1 byte, solo per celle relay)"""
        return self.relay if self.is_relay else None
    
    @property
    def stream_id(self) -> Optional[int]:
        """Stream ID (2 bytes, solo per celle relay)"""
        return self.streamid if self.is_relay else None
    
    @property
    def digest_field(self) -> Optional[bytes]:
        """Digest (6 bytes, solo per celle relay)"""
        return self.digest if self.is_relay else None
    
    @property
    def data_length(self) -> Optional[int]:
        """Lunghezza dati (2 bytes, solo per celle relay)"""
        return self.length if self.is_relay else None
    
    @property
    def payload(self) -> bytes:
        """Payload dati"""
        return self.data
    
    @property
    def effective_data(self) -> bytes:
        """Dati effettivi senza padding (solo per celle relay)"""
        if self.is_relay and hasattr(self, 'length'):
            return self.data[:self.length]
        return self.data
    
    def __repr__(self) -> str:
        if self.is_relay:
            return (f"TorCell(circid={self.circid}, cmd={self.cmd}, "
                   f"relay={self.relay}, streamid={self.streamid}, "
                   f"length={self.length}, is_relay=True)")
        else:
            return f"TorCell(circid={self.circid}, cmd={self.cmd}, is_relay=False)"
    
    def __len__(self) -> int:
        """Restituisce sempre 512 bytes come da specifica Tor"""
        return 512
    
def encode_payload(params: List[bytes]) -> bytes:
    """
    Encode a list of byte parameters into a single payload using 4-byte length prefix.
    """
    payload = b''.join(struct.pack('>I', len(p)) + p for p in params)
    return payload

def decode_payload(payload: bytes) -> List[bytes]:
    """
    Decode a payload with length-prefixed parameters back into a list of bytes.
    """
    payload = payload.rstrip('\0')

    params = []
    i = 0
    while i < len(payload):
        if i + 4 > len(payload):
            raise ValueError("Incomplete length prefix in payload")
        length = struct.unpack('>I', payload[i:i+4])[0]
        i += 4
        if i + length > len(payload):
            raise ValueError("Parameter length exceeds payload size")
        params.append(payload[i:i+length])
        i += length
    return params

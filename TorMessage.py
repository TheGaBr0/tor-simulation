import struct
from typing import Union, Optional, List

class TorCommands:
    CREATE = b'\x00'
    CREATED = b'\x01'
    RELAY = b'\x03'

class RelayCommands:
    EXTEND = b'\x00'
    EXTENDED = b'\x01'
    BEGIN = b'\x02'
    CONNECTED = b'\x03'
    END = b'\x04'
    DATA = b'\x05'

class TorCell:
    """
    Classe per gestire le celle del protocollo Tor.
    Supporta sia celle standard che celle relay.
    Circuit ID può essere fornito come int o bytes.
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
    
    def __init__(self, circid: Union[int, bytes], cmd: bytes, data: bytes = b'', 
                 relay: bytes = b'\x00', streamid: bytes = b'\x00\x00', 
                 digest: bytes = b'', length: bytes = b'\x00\x00'):
        """
        Inizializza una cella Tor.
        
        Args:
            circid: Circuit ID (int o 2 bytes) - se int, viene convertito automaticamente
            cmd: Command (1 byte) - usa TorCommands per determinare il tipo
            data: Dati della cella
            relay: Relay command (1 byte, solo per celle relay)
            streamid: Stream ID (2 bytes, solo per celle relay)
            digest: Digest (6 bytes, solo per celle relay)
            length: Lunghezza dei dati (2 bytes, solo per celle relay)
        """
        # Convert circid to bytes if it's an integer
        if isinstance(circid, int):
            if circid < 0 or circid > 65535:  # 2^16 - 1
                raise ValueError(f"Circuit ID deve essere tra 0 e 65535, ricevuto {circid}")
            self.circid = circid.to_bytes(self.CIRCID_SIZE, byteorder='big')
            self._circid_int = circid  # Store the original int for easy access
        else:
            self.circid = self._ensure_bytes_length(circid, self.CIRCID_SIZE)
            self._circid_int = int.from_bytes(self.circid, byteorder='big')
        
        self.cmd = self._ensure_bytes_length(cmd, self.CMD_SIZE)
        
        if self._is_relay_cell():
            self.relay = self._ensure_bytes_length(relay, self.RELAY_SIZE)
            self.streamid = self._ensure_bytes_length(streamid, self.STREAMID_SIZE)
            self.digest = self._ensure_bytes_length(digest, self.DIGEST_SIZE) if digest else b'\x00' * self.DIGEST_SIZE
            
            # If length is not provided, calculate it from data length
            if length == b'\x00\x00':
                data_len = len(data)
                self.length = struct.pack('>H', data_len)
            else:
                self.length = self._ensure_bytes_length(length, self.LEN_SIZE)
            
            # Assicura che i dati non superino la dimensione massima
            self.data = data[:self.DATA_SIZE] if data else b''
            # Padding dei dati se necessario
            self.data = self.data.ljust(self.DATA_SIZE, b'\x00')
        else:
            # Cella standard
            self.data = data[:self.STANDARD_DATA_SIZE] if data else b''
            # Padding dei dati se necessario
            self.data = self.data.ljust(self.STANDARD_DATA_SIZE, b'\x00')
    
    def _is_relay_cell(self) -> bool:
        """Helper interno per determinare se è una cella relay basato sul comando"""
        return self.cmd == TorCommands.RELAY
    
    def _ensure_bytes_length(self, data: bytes, expected_length: int) -> bytes:
        """Assicura che i bytes abbiano la lunghezza corretta, aggiungendo padding se necessario"""
        if len(data) > expected_length:
            return data[:expected_length]
        return data.ljust(expected_length, b'\x00')
    
    def to_bytes(self) -> bytes:
        """
        Converte la cella in bytes per l'invio.
        
        Returns:
            bytes: Rappresentazione binaria della cella
        """
        if self._is_relay_cell():
            # Formato: CircID(2) + CMD(1) + Relay(1) + StreamID(2) + Digest(6) + Len(2) + DATA(498)
            return (self.circid + 
                   self.cmd + 
                   self.relay + 
                   self.streamid + 
                   self.digest + 
                   self.length + 
                   self.data)
        else:
            # Formato: CircID(2) + CMD(1) + DATA(509)
            return self.circid + self.cmd + self.data
    
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
        circid = data[:2]
        cmd = data[2:3]
        
        # Determina se è una cella relay controllando il comando
        relay_cmd_check = cmd == TorCommands.RELAY
        
        if relay_cmd_check:
            # Parsing come cella relay
            relay = data[3:4]
            streamid = data[4:6]
            digest = data[6:12]
            length = data[12:14]
            payload = data[14:]
            
            return cls(
                circid=circid,
                cmd=cmd,
                relay=relay,
                streamid=streamid,
                digest=digest,
                length=length,
                data=payload
            )
        else:
            # Parsing come cella standard
            payload = data[3:]
            return cls(
                circid=circid,
                cmd=cmd,
                data=payload
            )
    
    # Proprietà per accesso ai campi
    @property
    def circuit_id(self) -> bytes:
        """Circuit ID come bytes (2 bytes)"""
        return self.circid
    
    @property
    def circuit_id_int(self) -> int:
        """Circuit ID come integer"""
        return self._circid_int
    
    @property
    def command(self) -> bytes:
        """Command (1 byte)"""
        return self.cmd
    
    @property
    def relay_command(self) -> Optional[bytes]:
        """Relay command (1 byte, solo per celle relay)"""
        return self.relay if self._is_relay_cell() else None
    
    @property
    def stream_id(self) -> Optional[bytes]:
        """Stream ID (2 bytes, solo per celle relay)"""
        return self.streamid if self._is_relay_cell() else None
    
    @property
    def digest_field(self) -> Optional[bytes]:
        """Digest (6 bytes, solo per celle relay)"""
        return self.digest if self._is_relay_cell() else None
    
    @property
    def data_length(self) -> Optional[bytes]:
        """Lunghezza dati (2 bytes, solo per celle relay)"""
        return self.length if self._is_relay_cell() else None
    
    @property
    def payload(self) -> bytes:
        """Payload dati"""
        return self.data
    
    @property
    def effective_data(self) -> bytes:
        """Dati effettivi senza padding (solo per celle relay)"""
        if self._is_relay_cell() and hasattr(self, 'length'):
            # Convert length bytes to int to slice data
            length_int = struct.unpack('>H', self.length)[0]
            return self.data[:length_int]
        return self.data
    
    def is_relay_type(self) -> bytes:
        """Restituisce il comando della cella (usa TorCommands.RELAY per celle relay)"""
        return self.cmd
    
    def __repr__(self) -> str:
        if self._is_relay_cell():
            return (f"TorCell(circid={self._circid_int}, cmd={self.cmd.hex()}, "
                   f"relay={self.relay.hex()}, streamid={self.streamid.hex()}, "
                   f"length={self.length.hex()}, type=RELAY)")
        else:
            return f"TorCell(circid={self._circid_int}, cmd={self.cmd.hex()}, type=STANDARD)"
    
    def __len__(self) -> int:
        """Restituisce sempre 512 bytes come da specifica Tor"""
        return 512

def encode_payload(params: List[bytes]) -> bytes:
    """
    Encode a list of byte parameters into a single payload using 4-byte length prefix.
    """
    payload = b''.join(struct.pack('>I', len(p)) + p for p in params)
    return payload

def decode_payload(payload: bytes, num_params: int) -> List[bytes]:
    params = []
    i = 0
    for _ in range(num_params):
        if i + 4 > len(payload):
            raise ValueError("Incomplete length prefix in payload")
        length = struct.unpack('>I', payload[i:i+4])[0]
        i += 4
        if i + length > len(payload):
            raise ValueError("Parameter length exceeds payload size")
        params.append(payload[i:i+length])
        i += length
    return params

# Helper functions for converting between int and bytes
def int_to_bytes(value: int, length: int) -> bytes:
    """Convert integer to bytes with specified length"""
    return value.to_bytes(length, byteorder='big')

def bytes_to_int(data: bytes) -> int:
    """Convert bytes to integer"""
    return int.from_bytes(data, byteorder='big')

# Convenience functions for common conversions
def circid_from_int(value: int) -> bytes:
    """Convert circuit ID from int to bytes"""
    return int_to_bytes(value, 2)

def cmd_from_int(value: int) -> bytes:
    """Convert command from int to bytes"""
    return int_to_bytes(value, 1)

def streamid_from_int(value: int) -> bytes:
    """Convert stream ID from int to bytes"""
    return int_to_bytes(value, 2)

def length_from_int(value: int) -> bytes:
    """Convert length from int to bytes"""
    return int_to_bytes(value, 2)




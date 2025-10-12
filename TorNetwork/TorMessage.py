import struct
from typing import Union, Optional, List


class TorCommands:
    """Standard Tor cell command types"""
    CREATE = b'\x00'
    CREATED = b'\x01'
    RELAY = b'\x03'
    DESTROY = b'\x04'


class RelayCommands:
    """Relay cell command subtypes for circuit extension and data transmission"""
    EXTEND = b'\x00'
    EXTENDED = b'\x01'
    BEGIN = b'\x02'
    CONNECTED = b'\x03'
    END = b'\x04'
    DATA = b'\x05'


class TorCell:
    """
    Tor protocol cell implementation.
    Supports both standard cells (CREATE, CREATED, DESTROY) and relay cells (RELAY).
    All cells are exactly 512 bytes as per Tor specification.
    """
    
    # Fixed field sizes (in bytes)
    CIRCID_SIZE = 2
    CMD_SIZE = 1
    RELAY_SIZE = 1
    STREAMID_SIZE = 2
    DIGEST_SIZE = 6
    LEN_SIZE = 2
    DATA_SIZE = 498  # Relay cell payload size
    STANDARD_DATA_SIZE = 509  # Standard cell payload size
    
    # Total cell sizes (always 512 bytes)
    STANDARD_CELL_SIZE = CIRCID_SIZE + CMD_SIZE + STANDARD_DATA_SIZE
    RELAY_CELL_SIZE = CIRCID_SIZE + CMD_SIZE + RELAY_SIZE + STREAMID_SIZE + DIGEST_SIZE + LEN_SIZE + DATA_SIZE
    
    def __init__(self, circid: Union[int, bytes], cmd: bytes, data: bytes = b'', 
                 relay: bytes = b'\x00', streamid: bytes = b'\x00\x00', 
                 digest: bytes = b'', length: bytes = b'\x00\x00'):
        """
        Initialize a Tor cell.
        """
        # Convert circuit ID to bytes if provided as integer
        if isinstance(circid, int):
            if circid < 0 or circid > 65535:  # Valid range for 2-byte circuit ID
                raise ValueError(f"Circuit ID must be between 0 and 65535, got {circid}")
            self.circid = circid.to_bytes(self.CIRCID_SIZE, byteorder='big')
            self._circid_int = circid
        else:
            self.circid = self._ensure_bytes_length(circid, self.CIRCID_SIZE)
            self._circid_int = int.from_bytes(self.circid, byteorder='big')
        
        self.cmd = self._ensure_bytes_length(cmd, self.CMD_SIZE)
        
        # Handle relay cells differently from standard cells
        if self._is_relay_cell():
            self.relay = self._ensure_bytes_length(relay, self.RELAY_SIZE)
            self.streamid = self._ensure_bytes_length(streamid, self.STREAMID_SIZE)
            self.digest = self._ensure_bytes_length(digest, self.DIGEST_SIZE) if digest else b'\x00' * self.DIGEST_SIZE
            
            # Calculate length from data if not explicitly provided
            if length == b'\x00\x00':
                data_len = len(data)
                self.length = struct.pack('>H', data_len)
            else:
                self.length = self._ensure_bytes_length(length, self.LEN_SIZE)
            
            self.data = data
        else:
            self.data = data
    
    def _is_relay_cell(self) -> bool:
        """Check if this is a relay cell based on command byte"""
        return self.cmd == TorCommands.RELAY
    
    def _ensure_bytes_length(self, data: bytes, expected_length: int) -> bytes:
        """
        Ensure byte data has the correct length, padding with zeros if needed.
        Truncates if data is too long.
        """
        if len(data) > expected_length:
            return data[:expected_length]
        return data.ljust(expected_length, b'\x00')
    
    def to_bytes(self) -> bytes:
        """
        Serialize the cell to bytes for transmission.
        """
        if self._is_relay_cell():
            # Relay cell format: CircID(2) + CMD(1) + Relay(1) + StreamID(2) + Digest(6) + Len(2) + DATA(498)
            return (self.circid + 
                   self.cmd + 
                   self.relay + 
                   self.streamid + 
                   self.digest + 
                   self.length + 
                   self.data)
        else:
            # Standard cell format: CircID(2) + CMD(1) + DATA(509)
            return self.circid + self.cmd + self.data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'TorCell':
        """
        Deserialize a Tor cell from binary data.
        """
        if len(data) != 512:
            raise ValueError(f"Cell data must be exactly 512 bytes, got {len(data)}")
        
        # Parse common header fields
        circid = data[:2]
        cmd = data[2:3]
        
        # Determine cell type and parse accordingly
        if cmd == TorCommands.RELAY:
            # Parse relay cell fields
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
            # Parse standard cell
            payload = data[3:]
            return cls(
                circid=circid,
                cmd=cmd,
                data=payload
            )
    
    # Property accessors for cell fields
    
    @property
    def circuit_id(self) -> bytes:
        """Circuit ID as bytes (2 bytes)"""
        return self.circid
    
    @property
    def circuit_id_int(self) -> int:
        """Circuit ID as integer (0-65535)"""
        return self._circid_int
    
    @property
    def command(self) -> bytes:
        """Command byte (1 byte)"""
        return self.cmd
    
    @property
    def relay_command(self) -> Optional[bytes]:
        """Relay command byte (1 byte, relay cells only)"""
        return self.relay if self._is_relay_cell() else None
    
    @property
    def stream_id(self) -> Optional[bytes]:
        """Stream ID (2 bytes, relay cells only)"""
        return self.streamid if self._is_relay_cell() else None
    
    @property
    def digest_field(self) -> Optional[bytes]:
        """Digest field (6 bytes, relay cells only)"""
        return self.digest if self._is_relay_cell() else None
    
    @property
    def data_length(self) -> Optional[bytes]:
        """Data length field (2 bytes, relay cells only)"""
        return self.length if self._is_relay_cell() else None
    
    @property
    def payload(self) -> bytes:
        """Raw payload data"""
        return self.data
    
    @property
    def effective_data(self) -> bytes:
        """
        Actual data without padding (relay cells only).
        For standard cells, returns full payload.
        """
        if self._is_relay_cell() and hasattr(self, 'length'):
            # Extract actual data length and slice accordingly
            length_int = struct.unpack('>H', self.length)[0]
            return self.data[:length_int]
        return self.data
    
    def is_relay_type(self) -> bytes:
        """Return the command byte (use TorCommands.RELAY to check for relay cells)"""
        return self.cmd
    
    def __repr__(self) -> str:
        """String representation for debugging"""
        if self._is_relay_cell():
            return (f"TorCell(circid={self._circid_int}, cmd={self.cmd.hex()}, "
                   f"relay={self.relay.hex()}, streamid={self.streamid.hex()}, "
                   f"length={self.length.hex()}, type=RELAY)")
        else:
            return f"TorCell(circid={self._circid_int}, cmd={self.cmd.hex()}, type=STANDARD)"
    
    def __len__(self) -> int:
        """Always returns 512 bytes as per Tor specification"""
        return 512


def encode_payload(params: List[bytes], is_relay: bool = False) -> bytes:
    """
    Encode multiple byte parameters into a single payload using 4-byte length prefixes.
    Automatically pads to the correct size based on cell type.
    
    Format: [len1(4)][param1][len2(4)][param2]...
    """
    # Encode each parameter with its length prefix
    payload = b''.join(struct.pack('>I', len(p)) + p for p in params)
    
    # Determine target size based on cell type
    target_size = TorCell.DATA_SIZE if is_relay else TorCell.STANDARD_DATA_SIZE
    
    # Ensure payload fits within size constraints
    if len(payload) > target_size:
        payload = payload[:target_size]  # Truncate if too long
    else:
        payload = payload.ljust(target_size, b'\x00')  # Pad if too short
    
    return payload


def decode_payload(payload: bytes, num_params: int) -> List[bytes]:
    """
    Decode a payload into individual parameters using length prefixes.
    """
    params = []
    i = 0
    for _ in range(num_params):
        # Read length prefix
        if i + 4 > len(payload):
            raise ValueError("Incomplete length prefix in payload")
        length = struct.unpack('>I', payload[i:i+4])[0]
        i += 4
        
        # Read parameter data
        if i + length > len(payload):
            raise ValueError("Parameter length exceeds payload size")
        params.append(payload[i:i+length])
        i += length
    
    return params


# Conversion utility functions

def int_to_bytes(value: int, length: int) -> bytes:
    """Convert integer to big-endian bytes with specified length"""
    return value.to_bytes(length, byteorder='big')


def bytes_to_int(data: bytes) -> int:
    """Convert big-endian bytes to integer"""
    return int.from_bytes(data, byteorder='big')


# Convenience functions for common cell field conversions

def circid_from_int(value: int) -> bytes:
    """Convert circuit ID integer to 2-byte representation"""
    return int_to_bytes(value, 2)


def cmd_from_int(value: int) -> bytes:
    """Convert command integer to 1-byte representation"""
    return int_to_bytes(value, 1)


def streamid_from_int(value: int) -> bytes:
    """Convert stream ID integer to 2-byte representation"""
    return int_to_bytes(value, 2)


def length_from_int(value: int) -> bytes:
    """Convert length integer to 2-byte representation"""
    return int_to_bytes(value, 2)
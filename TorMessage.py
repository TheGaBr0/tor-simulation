import json
from enum import IntEnum

class TorCell:
    CELL_PAYLOAD_SIZE = 509

    def __init__(self, circ_id: int, command: str):
        self.circ_id = circ_id
        self.command = command

    def to_dict(self) -> dict:
        return {"circ_id": self.circ_id, "command": self.command}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict):
        command = data.get("command")
        if command == "RELAY":  
            relay_header = RelayHeader.from_dict(data["relay_header"])
            payload = bytes.fromhex(data["relay_payload"])
            return RelayCell(data["circ_id"], relay_header, payload)
        elif command == "CREATE": 
            payload = bytes.fromhex(data["payload"])
            return CreateCell(data["circ_id"], payload)
        elif command == "CREATED":
            payload = bytes.fromhex(data["payload"])
            return CreatedCell(data["circ_id"], payload)
        else:
            return cls(data["circ_id"], command)

    @classmethod
    def from_json(cls, json_str: str):
        data = json.loads(json_str)
        return cls.from_dict(data)


class RelayHeader:
    def __init__(self, relay_command: str, stream_id: int, digest: bytes, length: int):
        self.relay_command = relay_command
        self.stream_id = stream_id
        self.digest = digest
        self.length = length

    def to_dict(self) -> dict:

        return {
            "relay_command": self.relay_command,
            "stream_id": self.stream_id,
            "digest": self.digest.hex(),
            "length": self.length
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            relay_command=data["relay_command"],
            stream_id=data["stream_id"],
            digest=bytes.fromhex(data["digest"]),
            length=data["length"]
        )


class RelayCell(TorCell):
    def __init__(self, circ_id: int, relay_header: RelayHeader, relay_payload: bytes):
        super().__init__(circ_id, command="RELAY")  # 3 = RELAY
        self.relay_header = relay_header
        self.relay_payload = relay_payload

    def to_dict(self) -> dict:
        base = super().to_dict()
    
        base.update({
            "relay_header": self.relay_header.to_dict(),
            "relay_payload": self.relay_payload.hex()
        })
        return base

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class CreateCell(TorCell):
    def __init__(self, circ_id: int, payload: bytes):
        super().__init__(circ_id, command="CREATE")
        self.payload = payload

    def to_dict(self) -> dict:
        base = super().to_dict()
        base.update({"payload": self.payload.hex()})
        return base

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
class CreatedCell(TorCell):
    def __init__(self, circ_id: int, payload: bytes):
        super().__init__(circ_id, command="CREATED")
        self.payload = payload

    def to_dict(self) -> dict:
        base = super().to_dict()
        base.update({"payload": self.payload.hex()})
        return base

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
class FieldType(IntEnum):
    DH_PARAMETER_BYTES = 1
    DH_HASH_K_BYTES = 2
    TOR_CELL = 3
    IP = 4
    PORT = 5

def pack_field(ftype: FieldType, value) -> bytes:
    if ftype == FieldType.TOR_CELL:
        if not isinstance(value, TorCell):
            raise TypeError("Expected TorCell for TOR_CELL field")
        data = value.to_json().encode("utf-8")

    elif ftype == FieldType.PORT:
        if not isinstance(value, int):
            raise TypeError("Expected int for PORT field")
        data = value.to_bytes(2, "big")

    elif ftype == FieldType.IP:
        if not isinstance(value, str):
            raise TypeError("Expected str for IP field")
        data = value.encode("utf-8")

    elif ftype == FieldType.DH_PARAMETER_BYTES:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("Expected bytes for DH_BYTES field")
        data = bytes(value)
        
    elif ftype == FieldType.DH_HASH_K_BYTES:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("Expected bytes for DH_BYTES field")
        data = bytes(value)

    else:
        raise TypeError(f"Unsupported field type: {ftype}")

    # pack as: [ftype:1][len:4][data:len]
    return ftype.to_bytes(1, "big") + len(data).to_bytes(4, "big") + data


def unpack_fields(payload: bytes):
    fields = []
    i = 0
    while i < len(payload):
        ftype = FieldType(payload[i])
        length = int.from_bytes(payload[i+1:i+5], "big")
        data = payload[i+5:i+5+length]

        if ftype == FieldType.TOR_CELL:
            obj = TorCell.from_json(data.decode("utf-8"))
            fields.append((ftype, obj))

        elif ftype == FieldType.PORT:
            obj = int.from_bytes(data, "big")
            fields.append((ftype, obj))

        elif ftype == FieldType.IP:
            obj = data.decode("utf-8")
            fields.append((ftype, obj))

        elif ftype == FieldType.DH_PARAMETER_BYTES:
            fields.append((ftype, data))

        else:
            fields.append((ftype, data))  # raw fallback

        i += 5 + length

    return fields

def unpack_fields_dict(payload: bytes) -> dict[FieldType, object]:
    """
    Same as unpack_fields, but returns a dict keyed by FieldType.
    Assumes each FieldType appears at most once.
    """
    return {ft: val for ft, val in unpack_fields(payload)}
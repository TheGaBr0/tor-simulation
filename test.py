from TorMessage import *

# Create some fields
f1 = pack_field(FieldType.IP, "192.168.0.10")
f2 = pack_field(FieldType.PORT, 9050)
f3 = pack_field(FieldType.DH_BYTES, b"\x01\x02\x03")
f4 = pack_field(FieldType.TOR_CELL, CreateCell(42, b"hello"))

packet = f1 + f2 + f3 + f4

# Decode back
decoded = unpack_fields(packet)
for ft, val in decoded:
    print(ft, val)
    if isinstance(val, TorCell):
        print("  -> TorCell dict:", val.to_dict())
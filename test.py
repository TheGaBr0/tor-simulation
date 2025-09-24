from Cryptograpy_utils import *

def process_dh_handshake_request_debug(onion_pubkey: bytes):
    print(f"DEBUG DH Request: Public key type = {type(onion_pubkey)}")
    print(f"DEBUG DH Request: Public key length = {len(onion_pubkey)}")
    
    x1 = secrets.randbits(256)
    print(f"DEBUG DH Request: Generated x1 = {x1}")
    print(f"DEBUG DH Request: x1 bit_length = {x1.bit_length()}")
    
    g_x1 = pow(DH_GENERATOR, x1, DH_PRIME)
    print(f"DEBUG DH Request: g_x1 = {g_x1}")
    print(f"DEBUG DH Request: g_x1 bit_length = {g_x1.bit_length()}")
    
    g_x1_bytes = g_x1.to_bytes((g_x1.bit_length() + 7) // 8, 'big')
    print(f"DEBUG DH Request: g_x1_bytes length = {len(g_x1_bytes)}")
    
    try:
        payload_encrypted = rsa_encrypt(onion_pubkey, g_x1_bytes)
        print(f"DEBUG DH Request: Encrypted payload length = {len(payload_encrypted)}")
    except Exception as e:
        print(f"ERROR DH Request: Encryption failed: {e}")
        raise
    
    return x1, g_x1, payload_encrypted

def process_dh_handshake_response_debug(g_x1: int):
    print(f"DEBUG DH Response: Received g_x1 = {g_x1}")
    print(f"DEBUG DH Response: g_x1 bit_length = {g_x1.bit_length()}")
    
    y1 = secrets.randbits(256)
    print(f"DEBUG DH Response: Generated y1 = {y1}")
    
    g_y1 = pow(DH_GENERATOR, y1, DH_PRIME)
    print(f"DEBUG DH Response: g_y1 = {g_y1}")
    print(f"DEBUG DH Response: g_y1 bit_length = {g_y1.bit_length()}")
    
    K1 = pow(g_x1, y1, DH_PRIME)
    print(f"DEBUG DH Response: K1 = {K1}")
    print(f"DEBUG DH Response: K1 bit_length = {K1.bit_length()}")
    
    K1_bytes = K1.to_bytes((K1.bit_length() + 7) // 8, 'big')
    print(f"DEBUG DH Response: K1_bytes length = {len(K1_bytes)}")
    
    H_K1 = hashlib.sha256(K1_bytes).digest()
    print(f"DEBUG DH Response: H_K1 = {H_K1.hex()}")
    
    return y1, g_y1, H_K1, K1

def process_dh_handshake_final_debug(g_y1_bytes: bytes, x1: int):
    print(f"DEBUG DH Final: g_y1_bytes length = {len(g_y1_bytes)}")
    print(f"DEBUG DH Final: x1 = {x1}")
    
    g_y1 = int.from_bytes(g_y1_bytes, 'big')
    print(f"DEBUG DH Final: g_y1 = {g_y1}")
    print(f"DEBUG DH Final: g_y1 bit_length = {g_y1.bit_length()}")
    
    K1 = pow(g_y1, x1, DH_PRIME)
    print(f"DEBUG DH Final: K1 calcolato = {K1}")
    print(f"DEBUG DH Final: K1 bit_length = {K1.bit_length()}")
    
    K1_bytes = K1.to_bytes((K1.bit_length() + 7) // 8, 'big')
    print(f"DEBUG DH Final: K1_bytes length = {len(K1_bytes)}")
    
    H_K1 = hashlib.sha256(K1_bytes).digest()
    print(f"DEBUG DH Final: H_K1 = {H_K1.hex()}")
    
    return H_K1

def test_dh_consistency():
    print("=== TEST DH CONSISTENCY ===")
    
    # Simula handshake completo
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    
    # Genera chiavi RSA per test
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    print("1. Client genera richiesta...")
    x1, g_x1, payload_encrypted = process_dh_handshake_request_debug(public_key_pem)
    
    print("\n2. Node decripta e processa...")
    decrypted = rsa_decrypt(private_key_pem, payload_encrypted)
    g_x1_received = int.from_bytes(decrypted, 'big')
    print(f"g_x1 originale: {g_x1}")
    print(f"g_x1 ricevuto:  {g_x1_received}")
    print(f"Match: {g_x1 == g_x1_received}")
    
    print("\n3. Node genera risposta...")
    y1, g_y1, H_K1_node, K1_node = process_dh_handshake_response_debug(g_x1_received)
    
    print("\n4. Client calcola finale...")
    g_y1_bytes = g_y1.to_bytes((g_y1.bit_length() + 7) // 8, 'big')
    H_K1_client = process_dh_handshake_final_debug(g_y1_bytes, x1)
    
    print(f"\n=== RISULTATI ===")
    print(f"H_K1 Node:   {H_K1_node.hex()}")
    print(f"H_K1 Client: {H_K1_client.hex()}")
    print(f"MATCH: {H_K1_node == H_K1_client}")

if __name__ == "__main__":
    test_dh_consistency()
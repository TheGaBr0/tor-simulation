from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import hashlib
import socket


# ----------------------------
# RSA Key Management Utilities
# ----------------------------

def gen_rsa_keypair(key_size=2048):
    """
    Generate an RSA key pair for asymmetric encryption.

    Args:
        key_size (int): Size of the RSA key in bits (default: 2048)

    Returns:
        tuple[bytes, bytes]: (private_key_pem, public_key_pem) encoded in PEM format
    """
    # Generate RSA key pair with standard public exponent
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()

    # Serialize private key to PEM format (no password protection)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return priv_pem, pub_pem


def rsa_encrypt(pubkey_bytes: bytes, message: bytes) -> bytes:
    """
    Encrypt data using RSA public key encryption with OAEP padding.

    Args:
        pubkey_bytes (bytes): PEM-encoded RSA public key
        message (bytes): Plaintext data to encrypt

    Returns:
        bytes: Encrypted ciphertext
    """
    pubkey = serialization.load_pem_public_key(pubkey_bytes)
    return pubkey.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(privkey_bytes: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt RSA ciphertext using a private key.

    Args:
        privkey_bytes (bytes): PEM-encoded RSA private key
        ciphertext (bytes): Encrypted data to decrypt

    Returns:
        bytes: Decrypted plaintext
    """
    privkey = serialization.load_pem_private_key(privkey_bytes, password=None)
    return privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ----------------------------
# Hashing Utilities
# ----------------------------

def calculate_digest(K: int):
    """
    Compute a truncated SHA-256 digest of a shared secret.
    Used for key confirmation in Diffie-Hellman handshakes.

    Args:
        K (int): Shared secret from DH key exchange

    Returns:
        bytes: First 6 bytes of SHA-256 hash
    """
    K_bytes = data_to_bytes(K)
    return hashlib.sha256(K_bytes).digest()[:6]


# ----------------------------
# Diffie-Hellman Key Exchange
# ----------------------------

# Standard DH parameters (1536-bit prime for demonstration purposes)
DH_PRIME = 156874742607098651821626634042477471003674428306907731606877171083582008749286573492540571412903052668130173948362539242642440935298288088414972420471624731674095851642410264484465824786341360329232185144143602798461936161824250554262125726929613853159779007247066458429245413467002687309175140373752995883173
DH_GENERATOR = 2


def process_dh_handshake_request(onion_pubkey: bytes):
    """
    Generate the client's part of a Diffie-Hellman handshake (CREATE cell).
    Encrypts the DH public value with the relay's RSA public key.

    Args:
        onion_pubkey (bytes): PEM-encoded RSA public key of the target relay

    Returns:
        tuple: (x1, g^x1 mod p, encrypted_payload)
            - x1: Client's private DH exponent
            - g^x1: Client's public DH value
            - encrypted_payload: RSA-encrypted g^x1 for transmission
    """
    # Generate random private exponent
    x1 = secrets.randbits(256)
    
    # Compute public DH value: g^x1 mod p
    g_x1 = pow(DH_GENERATOR, x1, DH_PRIME)
    
    # Convert to bytes and encrypt with relay's public key
    g_x1_bytes = data_to_bytes(g_x1)
    g_x1_bytes_encrypted = rsa_encrypt(onion_pubkey, g_x1_bytes)
    
    return x1, g_x1, g_x1_bytes_encrypted


def process_dh_handshake_response(g_x1_bytes: bytes):
    """
    Generate the relay's response to a DH handshake (CREATED cell).
    Computes the shared secret and returns confirmation hash.

    Args:
        g_x1_bytes (bytes): Client's public DH value (g^x1)

    Returns:
        tuple: (y1, g^y1, H(K1), K1)
            - y1: Relay's private DH exponent
            - g^y1: Relay's public DH value
            - H(K1): Hash of shared secret for verification
            - K1: Computed shared secret
    """
    g_x1 = int.from_bytes(g_x1_bytes, 'big')

    # Generate relay's random private exponent
    y1 = secrets.randbits(256)

    # Compute relay's public DH value: g^y1 mod p
    g_y1 = pow(DH_GENERATOR, y1, DH_PRIME)

    # Compute shared secret: K1 = (g^x1)^y1 mod p
    K1 = pow(g_x1, y1, DH_PRIME)

    # Generate confirmation hash
    H_K1 = calculate_digest(K1)

    return y1, g_y1, H_K1, K1


def process_dh_handshake_final(g_y1_bytes: bytes, x1: int):
    """
    Complete the client's side of the DH handshake.
    Verifies the shared secret matches the relay's confirmation.

    Args:
        g_y1_bytes (bytes): Relay's public DH value (g^y1)
        x1 (int): Client's private DH exponent

    Returns:
        bytes: Hash of computed shared secret for verification
    """
    g_y1 = int.from_bytes(g_y1_bytes, 'big')
    
    # Compute shared secret: K1 = (g^y1)^x1 mod p
    K1 = pow(g_y1, x1, DH_PRIME)
    
    # Generate confirmation hash to verify with relay's hash
    H_K1 = calculate_digest(K1)
    
    return H_K1


# ----------------------------
# AES Symmetric Encryption
# ----------------------------

def aes_ctr_encrypt(plaintext: bytes, key_material: int, direction: str) -> tuple[bytes, bytes]:
    """
    Encrypt data using AES-128 in CTR mode with derived key and nonce.
    Used for onion layer encryption in Tor circuits.

    Args:
        plaintext (bytes): Data to encrypt
        key_material (int): Shared secret from DH (e.g., K1)
        direction (str): "forward" or "backward" for nonce derivation

    Returns:
        tuple[bytes, bytes]: (ciphertext, nonce)
    """
    # Derive 128-bit AES key from DH shared secret
    key_bytes = data_to_bytes(key_material)
    key_128 = hashlib.sha256(key_bytes).digest()[:16]

    # Derive deterministic nonce based on key and direction
    nonce = hashlib.sha256(key_bytes + direction.encode()).digest()[:16]

    # Perform AES-CTR encryption
    cipher = Cipher(algorithms.AES(key_128), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext, nonce


def aes_ctr_decrypt(ciphertext: bytes, key_material: int, direction: str) -> bytes:
    """
    Decrypt AES-128 CTR ciphertext using derived key and nonce.
    
    Args:
        ciphertext (bytes): Encrypted data
        key_material (int): Shared secret from DH (e.g., K1)
        direction (str): "forward" or "backward" (must match encryption)

    Returns:
        bytes: Decrypted plaintext
    """
    # Derive same key and nonce as during encryption
    key_bytes = data_to_bytes(key_material)
    key_128 = hashlib.sha256(key_bytes).digest()[:16]
    nonce = hashlib.sha256(key_bytes + direction.encode()).digest()[:16]

    # Perform AES-CTR decryption
    cipher = Cipher(algorithms.AES(key_128), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext


# ----------------------------
# Data Conversion Utilities
# ----------------------------

def data_to_bytes(value: object) -> bytes:
    """
    Convert various data types to bytes for cryptographic operations.
    Handles integers, IP addresses, and strings intelligently.

    Args:
        value: Data to convert (int, str, or bytes)

    Returns:
        bytes: Converted byte representation
    """
    if isinstance(value, int):
        # Convert integer to big-endian bytes
        return value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')
    
    elif isinstance(value, str):
        # Try parsing as IP address first
        try:
            # Attempt IPv4 conversion
            return socket.inet_aton(value)
        except OSError:
            try:
                # Attempt IPv6 conversion
                return socket.inet_pton(socket.AF_INET6, value)
            except OSError:
                # Fall back to UTF-8 encoding for regular strings
                return value.encode('utf-8')
    
    elif isinstance(value, bytes):
        # Already in bytes format
        return value
    
    else:
        # Convert other types to string, then to bytes
        return str(value).encode('utf-8')
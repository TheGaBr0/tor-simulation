from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import hashlib
import socket
# ----------------------------
# Utility per chiavi RSA
# ----------------------------
def gen_rsa_keypair(key_size=2048):
    """
    Generate an RSA key pair and return both keys as PEM-encoded bytes.

    Returns:
        tuple[bytes, bytes]: (private_key_pem, public_key_pem)
    """
    # Generate RSA key pair
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()

    # Serialize private key to PEM
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No password
    )

    # Serialize public key to PEM
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return priv_pem, pub_pem

def rsa_encrypt(pubkey_bytes: bytes, message: bytes) -> bytes:

    """
    Encrypt bytes using a PEM-encoded public key.
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
    Decrypt bytes using a PEM-encoded private key.
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
# Utility per hash
# ----------------------------

def calculate_digest(K: int):
    K_bytes = data_to_bytes(K)
    return hashlib.sha256(K_bytes).digest()[:6]


# ----------------------------
# Utility per diffie hellman
# ----------------------------

DH_PRIME = 156874742607098651821626634042477471003674428306907731606877171083582008749286573492540571412903052668130173948362539242642440935298288088414972420471624731674095851642410264484465824786341360329232185144143602798461936161824250554262125726929613853159779007247066458429245413467002687309175140373752995883173
DH_GENERATOR = 2

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets



def process_dh_handshake_request(onion_pubkey: bytes):
    """
    Genera la prima parte dell'handshake DH cifrata con la chiave pubblica del nodo.

    :param onion_pubkey: Chiave pubblica del nodo OR1 in formato PEM
    :return: tuple (x1, g^x1 % p, payload_cifrato)
    """
    # Genera x1 casuale (tipicamente 256 bit o più)
    x1 = secrets.randbits(256)
    
    # Calcola g^x1 mod p
    g_x1 = pow(DH_GENERATOR, x1, DH_PRIME)
    
    # Converte g^x1 in byte per cifratura
    g_x1_bytes =data_to_bytes(g_x1)
    
    g_x1_bytes_encrypted = rsa_encrypt(onion_pubkey, g_x1_bytes)
    
    return x1, g_x1, g_x1_bytes_encrypted


def process_dh_handshake_response(g_x1_bytes: bytes):
    """
    Simula la risposta di OR1 alla prima cella CREATE.

    :param or1_privkey: chiave privata RSA del nodo OR1
    :param payload_encrypted: payload della cella CREATE contenente g^x1 cifrato
    :return: tuple (y1, g^y1, H(K1), K1)
    """
    g_x1 = int.from_bytes(g_x1_bytes, 'big')

    # Genera y1 casuale (tipicamente 256 bit o più)
    y1 = secrets.randbits(256)

    # Calcola g^y1 mod p
    g_y1 = pow(DH_GENERATOR, y1, DH_PRIME)

    # Calcola il segreto condiviso K1 = (g^x1)^y1 mod p
    K1 = pow(g_x1, y1, DH_PRIME)

    
    H_K1 = calculate_digest(K1)

    return y1, g_y1, H_K1, K1

def process_dh_handshake_final(g_y1_bytes: bytes, x1: int):
    g_y1 = int.from_bytes(g_y1_bytes, 'big')
    
    # K1 = (g^y1)^x1 mod p = (g^x1)^y1 mod p
    K1 = pow(g_y1, x1, DH_PRIME)
    
    H_K1 = calculate_digest(K1)
    
    return H_K1

# ----------------------------
# Utility per aes
# ----------------------------

def aes_ctr_encrypt(plaintext: bytes, key_material: int, direction: str) -> tuple[bytes, bytes]:
    """
    Encrypts plaintext using AES-128 in CTR mode, deriving nonce from session key.
    
    :param plaintext: Data to encrypt
    :param key_material: Integer key material (e.g., K1 from DH)
    :param direction: "forward" or "backward" to differentiate nonce
    :return: (ciphertext, nonce)
    """
    # Convert key material to bytes and derive a 128-bit key
    key_bytes = data_to_bytes(key_material)
    key_128 = hashlib.sha256(key_bytes).digest()[:16]  # 16 bytes = 128 bits

    # Derive a deterministic nonce from key material + direction
    nonce = hashlib.sha256(key_bytes + direction.encode()).digest()[:16]

    # Encrypt with AES-CTR using derived nonce
    cipher = Cipher(algorithms.AES(key_128), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext, nonce


def aes_ctr_decrypt(ciphertext: bytes, key_material: int, direction: str) -> bytes:
    """
    Decrypts AES-128 CTR ciphertext using the same key material and nonce.
    
    :param ciphertext: Data to decrypt
    :param key_material: Integer key material (e.g., K1 from DH)
    :param nonce: Nonce used during encryption
    :return: plaintext
    """
    key_bytes = data_to_bytes(key_material)
    key_128 = hashlib.sha256(key_bytes).digest()[:16]  # 128-bit key

    nonce = hashlib.sha256(key_bytes + direction.encode()).digest()[:16]

    cipher = Cipher(algorithms.AES(key_128), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

# ----------------------------
# Utility per bytes
# ----------------------------

def data_to_bytes(value: object) -> bytes:
    if isinstance(value, int):
        # Convert integer to bytes
        return value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')
    elif isinstance(value, str):
        # First try to parse as IP address
        try:
            # Try IPv4 first
            return socket.inet_aton(value)
        except OSError:
            try:
                # If IPv4 fails, try IPv6
                return socket.inet_pton(socket.AF_INET6, value)
            except OSError:
                # If both IP formats fail, treat as regular string
                return value.encode('utf-8')
    elif isinstance(value, bytes):
        # Already bytes, return as-is
        return value
    else:
        # For other types, convert to string first, then to bytes
        return str(value).encode('utf-8')

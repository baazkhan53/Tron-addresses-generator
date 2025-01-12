import random
import ecdsa
import base58

def generate_private_key():
    """Generate a random private key."""
    return ''.join(random.choice('0123456789abcdef') for _ in range(64))

def private_to_public(private_key):
    """Convert a private key to a public key."""
    private_key_bytes = bytes.fromhex(private_key)
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.verifying_key
    public_key = b'\x04' + verifying_key.to_string()
    return public_key

def public_to_address(public_key):
    """Convert a public key to a TRON address."""
    sha256 = ecdsa.util.sha256(public_key)
    ripemd160 = ecdsa.util.ripemd160(sha256)
    tron_address = b'\x41' + ripemd160
    checksum = ecdsa.util.sha256(ecdsa.util.sha256(tron_address))[:4]
    return base58.b58encode(tron_address + checksum).decode()

def generate_tron_address():
    """Generate a TRON address and its private key."""
    private_key = generate_private_key()
    public_key = private_to_public(private_key)
    address = public_to_address(public_key)
    return address, private_key

# Generate a TRON address and private key
address, private_key = generate_tron_address()
print("TRON Address:", address)
print("Private Key:", private_key)

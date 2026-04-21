from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature
from second_lab.md5 import get_md5


class DSSManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self, key_size: int = 2048):
        self.private_key = dsa.generate_private_key(key_size=key_size)
        self.public_key = self.private_key.public_key()
        return self._serialize_keys()

    def _serialize_keys(self):
        if not self.private_key or not self.public_key:
            raise ValueError("Keys not generated")

        priv_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return priv_pem, pub_pem

    def load_private_key(self, pem_data: bytes):
        self.private_key = serialization.load_pem_private_key(pem_data, password=None)

    def load_public_key(self, pem_data: bytes):
        self.public_key = serialization.load_pem_public_key(pem_data)

    def _hash_data(self, data: bytes):
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(data)
        return hasher.finalize(), chosen_hash

    def sign(self, data: bytes) -> str:
        if not self.private_key:
            raise ValueError("Private key not loaded")

        digest, chosen_hash = self._hash_data(data)
        signature = self.private_key.sign(digest, Prehashed(chosen_hash))
        return signature.hex()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        if not self.public_key:
            raise ValueError("Public key not loaded")
        try:
            signature = bytes.fromhex(signature_hex)
            digest, chosen_hash = self._hash_data(data)
            self.public_key.verify(signature, digest, Prehashed(chosen_hash))
            return True
        except (InvalidSignature, ValueError):
            return False
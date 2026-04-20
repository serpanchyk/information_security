import time
import io
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class RSAManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self, key_size=2048):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        return self._serialize_keys()

    def _serialize_keys(self):
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

    def get_max_chunk_size(self, key_size_bits):
        return (key_size_bits // 8) - 66

    def encrypt_file(self, input_bytes, key_size_bits):
        if not self.public_key:
            raise ValueError("Public key not generated or loaded")

        chunk_size = self.get_max_chunk_size(key_size_bits)
        output = io.BytesIO()

        start_time = time.perf_counter()
        for i in range(0, len(input_bytes), chunk_size):
            chunk = input_bytes[i: i + chunk_size]
            encrypted_chunk = self.public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            output.write(encrypted_chunk)
        duration = time.perf_counter() - start_time

        return output.getvalue(), duration

    def decrypt_file(self, encrypted_bytes, key_size_bits):
        if not self.private_key:
            raise ValueError("Private key not loaded")

        rsa_block_size = key_size_bits // 8
        output = io.BytesIO()

        start_time = time.perf_counter()
        for i in range(0, len(encrypted_bytes), rsa_block_size):
            chunk = encrypted_bytes[i: i + rsa_block_size]
            decrypted_chunk = self.private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            output.write(decrypted_chunk)
        duration = time.perf_counter() - start_time

        return output.getvalue(), duration
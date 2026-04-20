import os
import pytest
from fourth_lab.rsa import RSAManager


@pytest.fixture
def rsa_manager():
    manager = RSAManager()
    manager.generate_keys(key_size=2048)
    return manager


def test_key_generation():
    manager = RSAManager()
    priv_pem, pub_pem = manager.generate_keys(key_size=1024)

    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem
    assert manager.private_key is not None
    assert manager.public_key is not None


def test_serialization_logic(rsa_manager):
    priv, pub = rsa_manager._serialize_keys()
    assert len(priv) > 0
    assert len(pub) > 0


def test_chunk_size_calculation(rsa_manager):
    size = rsa_manager.get_max_chunk_size(2048)
    assert size == 190


def test_encryption_decryption_cycle(rsa_manager):
    original_data = b"Hello world! This is a test for RSA chunking strategy."

    encrypted, enc_time = rsa_manager.encrypt_file(original_data, 2048)
    assert len(encrypted) > len(original_data)
    assert enc_time > 0

    decrypted, dec_time = rsa_manager.decrypt_file(encrypted, 2048)
    assert decrypted == original_data
    assert dec_time > 0


def test_large_file_chunking(rsa_manager):
    original_data = os.urandom(500)

    encrypted, _ = rsa_manager.encrypt_file(original_data, 2048)
    assert len(encrypted) == 768

    decrypted, _ = rsa_manager.decrypt_file(encrypted, 2048)
    assert decrypted == original_data


def test_empty_data(rsa_manager):
    empty_data = b""
    encrypted, _ = rsa_manager.encrypt_file(empty_data, 2048)
    decrypted, _ = rsa_manager.decrypt_file(encrypted, 2048)
    assert decrypted == b""


def test_error_handling_no_keys():
    manager = RSAManager()
    with pytest.raises(ValueError, match="Public key not generated or loaded"):
        manager.encrypt_file(b"test", 2048)

    with pytest.raises(ValueError, match="Private key not loaded"):
        manager.decrypt_file(b"test", 2048)


@pytest.mark.parametrize("key_size", [1024, 2048])
def test_different_key_sizes(key_size):
    manager = RSAManager()
    manager.generate_keys(key_size=key_size)
    data = b"Varying key size test"

    encrypted, _ = manager.encrypt_file(data, key_size)
    decrypted, _ = manager.decrypt_file(encrypted, key_size)
    assert decrypted == data
import pytest
import os
from .dss import DSSManager


@pytest.fixture
def dss_manager():
    manager = DSSManager()
    manager.generate_keys(key_size=1024)
    return manager


def test_key_generation():
    manager = DSSManager()
    priv_pem, pub_pem = manager.generate_keys(key_size=1024)

    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem
    assert manager.private_key is not None
    assert manager.public_key is not None


def test_sign_and_verify_success(dss_manager):
    data = b"Important financial transaction"
    signature_hex = dss_manager.sign(data)

    assert isinstance(signature_hex, str)
    assert len(signature_hex) > 0
    assert dss_manager.verify(data, signature_hex) is True


def test_verify_failure_with_modified_data(dss_manager):
    data = b"Original message"
    modified_data = b"Modified message"
    signature_hex = dss_manager.sign(data)

    assert dss_manager.verify(modified_data, signature_hex) is False


def test_verify_failure_with_corrupt_signature(dss_manager):
    data = b"Test data"
    signature_hex = dss_manager.sign(data)

    # Змінюємо один символ у hex-рядку підпису
    corrupt_signature = list(signature_hex)
    corrupt_signature[0] = '0' if corrupt_signature[0] != '0' else '1'
    corrupt_signature = "".join(corrupt_signature)

    assert dss_manager.verify(data, corrupt_signature) is False


def test_serialization_and_loading():
    manager = DSSManager()
    priv_pem, pub_pem = manager.generate_keys(key_size=1024)

    new_manager = DSSManager()
    new_manager.load_private_key(priv_pem)
    new_manager.load_public_key(pub_pem)

    data = b"Cross-manager test"
    sig = manager.sign(data)
    assert new_manager.verify(data, sig) is True


def test_error_handling_no_keys():
    manager = DSSManager()
    with pytest.raises(ValueError, match="Private key not loaded"):
        manager.sign(b"data")

    with pytest.raises(ValueError, match="Public key not loaded"):
        manager.verify(b"data", "abcdef")
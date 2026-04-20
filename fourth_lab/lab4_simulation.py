import os
import time
from fourth_lab.rsa import RSAManager
from third_lab.rc5 import RC5
from second_lab.md5 import md5_hash_string
import pandas as pd
from cryptography.hazmat.primitives import serialization


def process_rsa_lab(file_path, key_size, action):
    if not file_path:
        return None, "No file selected", None

    rsa_mgr = RSAManager()
    k_bits = int(key_size)

    with open(file_path, "rb") as f:
        input_data = f.read()

    if action == "Encrypt":
        priv, pub = rsa_mgr.generate_keys(k_bits)
        with open("rsa_private.pem", "wb") as f:
            f.write(priv)
        with open("rsa_public.pem", "wb") as f:
            f.write(pub)

        result_data, duration = rsa_mgr.encrypt_file(input_data, k_bits)
        out_path = "output.rsa"
        with open(out_path, "wb") as f:
            f.write(result_data)

        return out_path, f"Encrypted in {duration:.6f}s", "rsa_public.pem"

    else:
        if not os.path.exists("rsa_private.pem"):
            return None, "Private key file missing", None

        with open("rsa_private.pem", "rb") as f:
            rsa_mgr.private_key = serialization.load_pem_private_key(f.read(), password=None)

        result_data, duration = rsa_mgr.decrypt_file(input_data, k_bits)
        out_path = "decrypted_output.bin"
        with open(out_path, "wb") as f:
            f.write(result_data)

        return out_path, f"Decrypted in {duration:.6f}s", "rsa_private.pem"


def run_automated_benchmark(key_size):
    k_bits = int(key_size)
    results = []

    rsa_mgr = RSAManager()
    rsa_mgr.generate_keys(k_bits)

    rc5_key = md5_hash_string("benchmark_secret").encode()[:16]
    rc5_inst = RC5(rc5_key)
    iv = os.urandom(8)

    test_sizes_bytes = [10, 190, 1000, 20_000, 1_000_000]

    for num_bytes in test_sizes_bytes:
        test_data = os.urandom(num_bytes)

        _, rsa_time = rsa_mgr.encrypt_file(test_data, k_bits)

        start_rc5 = time.perf_counter()
        rc5_inst.encrypt_cbc(test_data, iv)
        rc5_time = time.perf_counter() - start_rc5

        ratio = rsa_time / rc5_time if rc5_time > 0 else 0

        results.append({
            "Data Size": f"{num_bytes} bytes",
            "RSA Time (s)": f"{rsa_time:.6f}",
            "RC5 Time (s)": f"{rc5_time:.6f}",
            "Ratio (RSA/RC5)": f"{ratio:.2f}x slower"
        })

    table_data = [[r["Data Size"], r["RSA Time (s)"], r["RC5 Time (s)"], r["Ratio (RSA/RC5)"]] for r in results]

    return table_data
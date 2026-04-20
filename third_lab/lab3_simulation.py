from .rc5 import RC5
from second_lab.md5 import md5_hash_string


def process_rc5_lab(input_text: str, password_str: str, iv_str: str, mode: str, w_val: int, r_val: int, b_val: int):
    try:
        if not input_text:
            return "Помилка", "Текст не може бути порожнім", None

        md5_hex = md5_hash_string(password_str)
        key = md5_hex.encode('utf-8')[:b_val].ljust(b_val, b'\x00')

        iv = iv_str.encode('utf-8')

        rc5 = RC5(key, w=w_val, r=r_val)

        if mode == "Encrypt":
            data = input_text.encode('utf-8')
            encrypted_bytes = rc5.encrypt_cbc(data, iv)
            result = encrypted_bytes.hex()
            output_filename = "rc5_encrypted.txt"

        else:
            try:
                data = bytes.fromhex(input_text.strip())
            except ValueError:
                return "Помилка формату", "Для розшифрування вхідні дані мають бути у форматі Hex", None

            decrypted_bytes = rc5.decrypt_cbc(data, iv)
            result = decrypted_bytes.decode('utf-8')
            output_filename = "rc5_decrypted.txt"

        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(result)

        return result, f"Успішно ({mode})", output_filename

    except Exception as e:
        return "System Error", str(e), None
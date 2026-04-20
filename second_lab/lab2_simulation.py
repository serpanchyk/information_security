import os
from .md5 import md5_hash_string, md5_hash_file


def process_md5_lab(input_text: str, input_file: str, expected_hash: str):
    output_filename = "md5_result.txt"
    result_hash = ""
    target = ""

    try:
        if input_file is not None:
            result_hash = md5_hash_file(input_file)
            target = f"File: {os.path.basename(input_file)}"
        elif input_text:
            result_hash = md5_hash_string(input_text)
            target = f"Text: '{input_text}'"
        else:
            result_hash = md5_hash_string("")
            target = "Text: '' (Empty string)"

        with open(output_filename, 'w') as f:
            f.write(result_hash)

        integrity_status = "Not checked"
        if expected_hash:
            if expected_hash.strip().lower() == result_hash.lower():
                integrity_status = "INTEGRITY VERIFIED: Hashes match."
            else:
                integrity_status = "INTEGRITY FAILED: Hashes do not match."

        return target, result_hash.upper(), integrity_status, output_filename

    except Exception as e:
        return f"Error", str(e), "Error", None
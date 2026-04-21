import gradio as gr
from first_lab.lab_simulation import process_lab_simulation
from second_lab.lab2_simulation import process_md5_lab
from third_lab.lab3_simulation import process_rc5_lab
from fourth_lab.lab4_simulation import process_rsa_lab, run_automated_benchmark
from fifth_lab.lab5_simulation import generate_keys_ui, sign_ui, verify_ui

def create_ui():
    theme = gr.themes.Soft(
        primary_hue="blue",
        text_size="lg",
    )

    lit = "### Results"
    lit_2 = "Enter string here..."

    with gr.Blocks(theme=theme, title="Cryptography Labs") as app:
        gr.Markdown("# Cryptography & Security Labs")
        gr.Markdown("Select a laboratory assignment from the tabs below.")

        with gr.Tabs():
            with gr.TabItem("Home"):
                gr.Markdown("### Welcome")
                gr.Markdown("""
                This application allows you to run and verify cryptography laboratory assignments.

                **Available Modules:**
                1. **Lab 1: LCG & Period Finding**
                2. **Lab 2: MD5**
                3. **Lab 3: RC5**
                4. **Lab 4: RSA**
                5. **Lab 5: DSS Digital Signature**
                """)

            with gr.TabItem("Lab 1: LCG Analysis"):
                gr.Markdown("## LCG Generator with Period Finding")
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### Configuration")
                        in_mod = gr.Number(label="Modulus (m)", value=2 ** 23 - 1, precision=0)
                        in_mult = gr.Number(label="Multiplier (a)", value=1000, precision=0)
                        in_inc = gr.Number(label="Increment (c)", value=377, precision=0)
                        in_seed = gr.Number(label="Seed", value=7, precision=0)
                        in_size = gr.Number(label="Sequence Size", value=100000, precision=0)
                        btn = gr.Button("Analyze", variant="primary")
                    with gr.Column():
                        gr.Markdown(lit)
                        out_status = gr.Textbox(label="Status")
                        out_period = gr.Textbox(label="Calculated Period (T)")
                        with gr.Row():
                            out_pi_lcg = gr.Textbox(label="PI (LCG)")
                            out_pi_lib = gr.Textbox(label="PI (Lib)")
                        out_seq = gr.Textbox(label="Preview")
                        out_file = gr.File(label="Full Sequence")

                btn.click(
                    fn=process_lab_simulation,
                    inputs=[in_mod, in_mult, in_inc, in_seed, in_size],
                    outputs=[out_status, out_pi_lcg, out_pi_lib, out_seq, out_file, out_period]
                )

            with gr.TabItem("Lab 2: MD5"):
                gr.Markdown("## MD5 Hash Generator & Integrity Checker")
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### Input Data")
                        in_text_md5 = gr.Textbox(label="Text to hash", placeholder=lit_2)
                        gr.Markdown("**OR**")
                        in_file_md5 = gr.File(label="Upload File to hash", type="filepath")
                        gr.Markdown("### Verification")
                        in_expected_hash = gr.Textbox(label="Expected MD5 Hash (Hex)", placeholder="Paste hex hash to verify integrity...")
                        btn_md5 = gr.Button("Calculate Hash & Verify", variant="primary")
                    with gr.Column():
                        gr.Markdown(lit)
                        out_target = gr.Textbox(label="Processed Target")
                        out_hash = gr.Textbox(label="MD5 Hash (Hex)")
                        out_integrity = gr.Textbox(label="Integrity Status")
                        out_result_file = gr.File(label="Download Result File")

                btn_md5.click(
                    fn=process_md5_lab,
                    inputs=[in_text_md5, in_file_md5, in_expected_hash],
                    outputs=[out_target, out_hash, out_integrity, out_result_file]
                )

            with gr.TabItem("Lab 3: RC5"):
                gr.Markdown("## RC5 CBC Encryption & Decryption")
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### Parameters")
                        in_text_rc5 = gr.Textbox(label="Text (Plaintext or Hex Ciphertext)", value="Я люблю СШІ", lines=4)
                        in_key_rc5 = gr.Textbox(label="Password (Hashed via MD5 to 32 bytes)", value="MySecretPassword")
                        in_iv_rc5 = gr.Textbox(label="Initialization Vector (IV)", value="41167228d6cb5338")
                        with gr.Row():
                            in_w = gr.Dropdown(choices=[16, 32, 64], label="Word Size (w)", value=32)
                            in_r = gr.Number(label="Rounds (r)", value=12, precision=0)
                            in_b = gr.Number(label="Key length in bytes (b)", value=32, precision=0)
                        in_mode_rc5 = gr.Radio(["Encrypt", "Decrypt"], label="Operation", value="Encrypt")
                        btn_rc5 = gr.Button("Execute", variant="primary")
                    with gr.Column():
                        gr.Markdown(lit)
                        out_status_rc5 = gr.Textbox(label="Status")
                        out_result_rc5 = gr.Textbox(label="Output Data", lines=4)
                        out_file_rc5 = gr.File(label="Download Result")

                btn_rc5.click(
                    fn=process_rc5_lab,
                    inputs=[in_text_rc5, in_key_rc5, in_iv_rc5, in_mode_rc5, in_w, in_r, in_b],
                    outputs=[out_result_rc5, out_status_rc5, out_file_rc5]
                )

            with gr.TabItem("Lab 4: RSA"):
                gr.Markdown("## RSA File Encryption (Chunking Strategy)")
                with gr.Row():
                    with gr.Column():
                        file_input = gr.File(label="Select File", type="filepath")
                        rsa_bits = gr.Dropdown([1024, 2048, 4096], label="Key Size", value=2048)
                        rsa_action = gr.Radio(["Encrypt", "Decrypt"], label="Action", value="Encrypt")
                        btn_run = gr.Button("Execute", variant="primary")
                    with gr.Column():
                        file_output = gr.File(label="Result File")
                        stats_output = gr.Textbox(label="Status")
                        key_output = gr.File(label="Key (PEM)")

                btn_run.click(
                    process_rsa_lab,
                    inputs=[file_input, rsa_bits, rsa_action],
                    outputs=[file_output, stats_output, key_output]
                )

                gr.Markdown("### Automated Scaling Benchmark")
                gr.Markdown("This test generates random data objects of increasing sizes to compare encryption speed.")
                rsa_bits_bench = gr.Dropdown([1024, 2048, 4096], label="RSA Key Size for Test", value=2048)
                btn_bench = gr.Button("Run Automated Benchmark", variant="secondary")

                bench_table = gr.Dataframe(
                    headers=["Data Size", "RSA Time (s)", "RC5 Time (s)", "Comparison"],
                    datatype=["str", "str", "str", "str"],
                    label="Scaling Results"
                )

                btn_bench.click(
                    run_automated_benchmark,
                    inputs=[rsa_bits_bench],
                    outputs=[bench_table]
                )

            with gr.TabItem("Lab 5: DSS"):
                gr.Markdown("## Digital Signature Standard (DSS) Generator & Verifier")

                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### 1. Key Generation")
                        dsa_key_size = gr.Dropdown([1024, 2048, 3072], label="DSA Key Size", value=2048)
                        btn_gen_keys = gr.Button("Generate Keys")
                    with gr.Column():
                        out_priv_key = gr.File(label="Private Key (PEM)")
                        out_pub_key = gr.File(label="Public Key (PEM)")
                        out_key_status = gr.Textbox(label="Status")

                btn_gen_keys.click(
                    fn=generate_keys_ui,
                    inputs=[dsa_key_size],
                    outputs=[out_priv_key, out_pub_key, out_key_status]
                )

                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### 2. Sign Data")
                        sign_text = gr.Textbox(label="Text to sign", placeholder=lit_2)
                        sign_file = gr.File(label="OR Upload File to sign", type="filepath")
                        sign_priv_key = gr.File(label="Private Key (PEM) required", type="filepath")
                        btn_sign = gr.Button("Sign Data", variant="primary")
                    with gr.Column():
                        out_sig_hex = gr.Textbox(label="Generated Signature (Hex)")
                        out_sig_status = gr.Textbox(label="Status")
                        out_sig_file = gr.File(label="Download Signature File")

                btn_sign.click(
                    fn=sign_ui,
                    inputs=[sign_text, sign_file, sign_priv_key],
                    outputs=[out_sig_hex, out_sig_status, out_sig_file]
                )

                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### 3. Verify Data")
                        verify_text = gr.Textbox(label="Text to verify", placeholder=lit_2)
                        verify_file = gr.File(label="OR Upload File to verify", type="filepath")
                        verify_pub_key = gr.File(label="Public Key (PEM) required", type="filepath")
                        verify_sig_hex = gr.Textbox(label="Signature (Hex)")
                        verify_sig_file = gr.File(label="OR Upload Signature File", type="filepath")
                        btn_verify = gr.Button("Verify Signature", variant="secondary")
                    with gr.Column():
                        out_verify_status = gr.Textbox(label="Verification Result")

                btn_verify.click(
                    fn=verify_ui,
                    inputs=[verify_text, verify_file, verify_pub_key, verify_sig_hex, verify_sig_file],
                    outputs=[out_verify_status]
                )

    return app

if __name__ == "__main__":
    ui = create_ui()
    ui.launch()
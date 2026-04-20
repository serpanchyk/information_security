import random
from .lcg import RandomNumberGenerator

def process_lab_simulation(mod_str, mult_str, inc_str, seed_str, size_str):
    output_filename = "output_sequence.txt"

    try:
        try:
            mod = int(mod_str)
            mult = int(mult_str)
            inc = int(inc_str)
            seed = int(seed_str)
            size = int(size_str)
        except ValueError:
            return "Error: All inputs must be valid integers.", "-", "-", "-", None, "-"

        lcg = RandomNumberGenerator(mod, mult, inc, seed)

        period = lcg.find_period()

        our_sequence = lcg.generate_sequence(size)
        our_pi = lcg.test_sequence(our_sequence)

        bench_generator = random.Random(seed)
        bench_sequence = [bench_generator.randint(1, 2**31 - 1) for _ in range(size)]
        bench_pi = lcg.test_sequence(bench_sequence)

        with open(output_filename, 'w') as f:
            f.write(str(our_sequence))

        preview = str(our_sequence[:50]) + ("..." if len(our_sequence) > 50 else "")
        status = "Success! Sequence generated and tested."

        return status, f"{our_pi:.5f}", f"{bench_pi:.5f}", preview, output_filename, str(period)

    except ValueError as ve:
        return f"Configuration Error: {str(ve)}", "-", "-", "-", None, "-"
    except Exception as e:
        return f"System Error: {str(e)}", "-", "-", "-", None, "-"
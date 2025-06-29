import subprocess

if __name__ == "__main__":
    print("[1] Building OPA input files from inventory + policies...")
    subprocess.run(["python3", "../input_builder/build_input.py"])

    print("[2] Running OPA evaluations on all input files...")
    subprocess.run(["python3", "../utils/opa_runner.py"])

    print("[✓] Done. Check evaluations/results for output.")

import subprocess
import json
import os
import uuid

def run_slither(contract_path):
    scan_id = str(uuid.uuid4())
    output_file = f"reports/{scan_id}.json"

    os.makedirs("reports", exist_ok=True)

    command = [
        "slither",
        contract_path,
        "--json",
        output_file
    ]

    subprocess.run(command, capture_output=True, text=True)

    return output_file
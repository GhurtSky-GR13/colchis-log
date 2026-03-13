import json
import time

FRAME_SIZE = 109

def get_last_frame_hash(log_path):
    with open(log_path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        if size < FRAME_SIZE:
            raise ValueError("Log file too small")
        f.seek(size - FRAME_SIZE)
        frame = f.read(FRAME_SIZE)
        return frame[-32:].hex()

def count_frames(log_path):
    with open(log_path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
    return size // FRAME_SIZE

def generate_proof(log_path, output_path=None):
    last_hash = get_last_frame_hash(log_path)
    frames = count_frames(log_path)
    proof = {
        "log_file": log_path,
        "frames": frames,
        "last_hash": last_hash,
        "timestamp": int(time.time())
    }
    if not output_path:
        output_path = log_path + ".proof.json"
    with open(output_path, "w") as f:
        json.dump(proof, f, indent=2)
    return output_path

def verify_proof(log_path, proof_path):
    with open(proof_path) as f:
        proof = json.load(f)
    return get_last_frame_hash(log_path) == proof["last_hash"]

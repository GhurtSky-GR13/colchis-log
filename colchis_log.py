import hashlib
import struct
import time
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

MAGIC = b'COLCHIS1'
VERSION = 1
HASH_SIZE = 32
HEADER_SIZE = 10
FRAME_FIELDS_SIZE = HASH_SIZE + 8 + 1 + 2 + 2 + HASH_SIZE  # 77
FRAME_TOTAL = FRAME_FIELDS_SIZE + HASH_SIZE  # 109


class ColchisLog:

    def __init__(self, path: str):
        self.path = Path(path)
        self.payload_dir = self.path.parent / 'payloads'
        self.payload_dir.mkdir(exist_ok=True)
        self.f = None

    def open(self, mode: str = 'rb') -> 'ColchisLog':
        self.f = self.path.open(mode)
        return self

    def close(self):
        if self.f:
            self.f.close()
            self.f = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def write_header(self):
        self.f.write(MAGIC)
        self.f.write(struct.pack('<BB', VERSION, 0))
        self.f.flush()

    def _save_payload(self, data: bytes) -> bytes:
        h = hashlib.sha256(data).digest()
        p = self.payload_dir / h.hex()
        try:
            fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
        except FileExistsError:
            pass
        return h

    def append_frame(self, parent_hash: bytes, timestamp: int,
                     node_type: int, actor_id: int,
                     flags: int, payload: bytes) -> bytes:
        if len(parent_hash) != HASH_SIZE:
            raise ValueError(f"parent_hash must be {HASH_SIZE} bytes")
        payload_ref = self._save_payload(payload)
        data = (parent_hash +
                struct.pack('<Q', timestamp) +
                struct.pack('<B', node_type) +
                struct.pack('<H', actor_id) +
                struct.pack('<H', flags) +
                payload_ref)
        frame_hash = hashlib.sha256(data).digest()
        self.f.write(data + frame_hash)
        return frame_hash

    def flush(self):
        if self.f:
            self.f.flush()

    def read_frames(self) -> list:
        self.f.seek(HEADER_SIZE)
        frames = []
        while True:
            data = self.f.read(FRAME_FIELDS_SIZE)
            if len(data) != FRAME_FIELDS_SIZE:
                break
            h = self.f.read(HASH_SIZE)
            payload_ref = data[45:77].hex()
            payload_path = self.payload_dir / payload_ref
            if payload_path.exists():
                try:
                    payload = payload_path.read_bytes().decode('utf-8', errors='replace')
                except Exception:
                    payload = "[binary data]"
            else:
                payload = "[missing]"
            frames.append({
                'frame_id': len(frames),
                'parent_hash': data[:32].hex(),
                'timestamp': int.from_bytes(data[32:40], 'little'),
                'datetime': time.ctime(int.from_bytes(data[32:40], 'little')),
                'node_type': data[40],
                'actor_id': int.from_bytes(data[41:43], 'little'),
                'flags': int.from_bytes(data[43:45], 'little'),
                'payload_ref': payload_ref,
                'frame_hash': h.hex(),
                'payload': payload
            })
        return frames

    def verify(self) -> bool:
        self.f.seek(0)
        if self.f.read(8) != MAGIC:
            logger.error("Invalid magic")
            return False
        ver, _ = struct.unpack('<BB', self.f.read(2))
        if ver != VERSION:
            logger.error("Invalid version")
            return False
        prev_hash = b'\x00' * HASH_SIZE
        n = 0
        while True:
            data = self.f.read(FRAME_FIELDS_SIZE)
            if len(data) != FRAME_FIELDS_SIZE:
                break
            frame_hash = self.f.read(HASH_SIZE)
            if len(frame_hash) != HASH_SIZE:
                logger.error("Truncated frame")
                return False
            if data[:32] != prev_hash:
                logger.error(f"Frame {n}: parent hash mismatch")
                return False
            if hashlib.sha256(data).digest() != frame_hash:
                logger.error(f"Frame {n}: hash mismatch")
                return False
            payload_ref = data[45:77]
            payload_path = self.payload_dir / payload_ref.hex()
            if not payload_path.exists():
                logger.error(f"Frame {n}: payload missing")
                return False
            actual = hashlib.sha256(payload_path.read_bytes()).digest()
            if actual != payload_ref:
                logger.error(f"Frame {n}: payload tampered")
                return False
            prev_hash = frame_hash
            n += 1
        logger.info(f"Verified {n} frames successfully")
        return True

    def dump(self):
        frames = self.read_frames()
        print(f"Total frames: {len(frames)}")
        for f in frames:
            print(f"\n--- Frame {f['frame_id']} ---")
            print(f"  Datetime:  {f['datetime']}")
            print(f"  Node type: {f['node_type']}")
            print(f"  Actor ID:  {f['actor_id']}")
            print(f"  Payload:   {f['payload'][:80]}")
            print(f"  Hash:      {f['frame_hash'][:16]}...")

import argparse
import time
import sys
import csv
import os
from pathlib import Path
from colchis_log import ColchisLog, HEADER_SIZE, FRAME_TOTAL, HASH_SIZE

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    HAS_PDF = True
except ImportError:
    HAS_PDF = False


def get_parent_hash(log) -> bytes:
    log.f.seek(0, 2)
    size = log.f.tell()
    if size <= HEADER_SIZE:
        return b'\x00' * HASH_SIZE
    if (size - HEADER_SIZE) % FRAME_TOTAL != 0:
        raise ValueError(f"Corrupted log: unexpected file size {size}")
    log.f.seek(-HASH_SIZE, 2)
    return log.f.read(HASH_SIZE)


def main():
    parser = argparse.ArgumentParser(description='Colchis Log CLI')
    subparsers = parser.add_subparsers(dest='command', required=True)

    init_parser = subparsers.add_parser('init')
    init_parser.add_argument('logfile')

    append_parser = subparsers.add_parser('append')
    append_parser.add_argument('logfile')
    append_parser.add_argument('--data', required=True)
    append_parser.add_argument('--node-type', type=int, default=1)
    append_parser.add_argument('--actor-id', type=int, default=1)
    append_parser.add_argument('--flags', type=int, default=0)

    verify_parser = subparsers.add_parser('verify')
    verify_parser.add_argument('logfile')

    dump_parser = subparsers.add_parser('dump')
    dump_parser.add_argument('logfile')

    export_parser = subparsers.add_parser('export')
    export_parser.add_argument('logfile')
    export_parser.add_argument('--format', choices=['csv', 'pdf'], default='csv')
    export_parser.add_argument('--output')

    proof_parser = subparsers.add_parser('proof')
    proof_parser.add_argument('logfile')

    vproof_parser = subparsers.add_parser('verify-proof')
    vproof_parser.add_argument('logfile')
    vproof_parser.add_argument('prooffile')

    args = parser.parse_args()

    if args.command == 'init':
        with ColchisLog(args.logfile).open('wb') as log:
            log.write_header()
        print(f"Log initialized: {args.logfile}")

    elif args.command == 'append':
        log_path = Path(args.logfile)
        if not log_path.exists():
            with ColchisLog(args.logfile).open('wb') as log:
                log.write_header()
        with ColchisLog(args.logfile).open('r+b') as log:
            parent = get_parent_hash(log)
            h = log.append_frame(
                parent, int(time.time()),
                args.node_type, args.actor_id,
                args.flags, args.data.encode('utf-8')
            )
            log.flush()
            print(f"Frame appended, hash: {h.hex()}")

    elif args.command == 'verify':
        with ColchisLog(args.logfile).open('rb') as log:
            ok = log.verify()
            print("✅ Valid" if ok else "❌ Invalid")
            sys.exit(0 if ok else 1)

    elif args.command == 'dump':
        with ColchisLog(args.logfile).open('rb') as log:
            log.dump()

    elif args.command == 'export':
        if not os.path.exists(args.logfile):
            print(f"Error: {args.logfile} not found")
            sys.exit(1)
        with ColchisLog(args.logfile).open('rb') as log:
            frames = log.read_frames()

        if args.format == 'csv':
            out = args.output or args.logfile.replace('.log', '_export.csv')
            with open(out, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['frame_id', 'parent_hash', 'timestamp',
                              'datetime', 'node_type', 'actor_id',
                              'flags', 'payload_ref', 'frame_hash', 'payload']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(frames)
            print(f"Exported to {out}")

        elif args.format == 'pdf':
            if not HAS_PDF:
                print("Error: reportlab not installed")
                sys.exit(1)
            out = args.output or args.logfile.replace('.log', '_export.pdf')
            c = canvas.Canvas(out, pagesize=letter)
            width, height = letter
            y = height - 40
            c.setFont("Helvetica", 8)
            c.drawString(40, y, f"Colchis Log: {args.logfile}")
            y -= 15
            c.drawString(40, y, f"Frames: {len(frames)}")
            y -= 30
            for f in frames:
                if y < 60:
                    c.showPage()
                    y = height - 40
                    c.setFont("Helvetica", 8)
                c.drawString(40, y, f"Frame {f['frame_id']}: {f['datetime']} "
                                    f"Type={f['node_type']} Actor={f['actor_id']}")
                y -= 12
                c.drawString(50, y, f"Hash: {f['frame_hash'][:32]}...")
                y -= 12
                c.drawString(50, y, f"Payload: {f['payload'][:60]}")
                y -= 20
            c.save()
            print(f"Exported to {out}")


    elif args.command == 'proof':
        from proof import generate_proof
        out = generate_proof(args.logfile)
        print(f"Proof saved: {out}")

    elif args.command == 'verify-proof':
        from proof import verify_proof
        ok = verify_proof(args.logfile, args.prooffile)
        print("✅ Proof VALID" if ok else "❌ Proof INVALID")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()

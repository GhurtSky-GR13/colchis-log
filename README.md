# Colchis Execution Log (CEL)

> Cryptographic, append-only execution log for AI systems.

## What is it?

Colchis Execution Log is a lightweight Python library that records every step
of an AI execution as a cryptographically linked chain of frames.
Each frame is SHA-256 hashed and linked to the previous one —
making any tampering immediately detectable.

## Features

- **Tamper-proof** — SHA-256 hash chain detects any modification
- **Payload verification** — every payload is content-addressed and verified
- **CLI tool** — init, append, verify, dump, export
- **Web interface** — browser-based log viewer
- **Export** — CSV and PDF reports
- **Zero cloud dependency** — works fully offline
- **Lightweight** — pure Python, minimal dependencies

## Use Cases

- AI audit trail (EU AI Act, GDPR compliance)
- LLM tool-call traceability
- Deterministic agent execution logging
- Safety-critical AI systems
- Reproducible research

## Quick Start

```bash
pip install flask reportlab
python cli.py init mylog.log
python cli.py append mylog.log --data "Agent started"
python cli.py verify mylog.log
python cli.py dump mylog.log
Web Interface
python webdemo.py
# Open http://127.0.0.1:5000
Export
python cli.py export mylog.log --format csv
python cli.py export mylog.log --format pdf
File Format
Each frame contains:
parent_hash — SHA-256 of previous frame (32 bytes)
timestamp — Unix timestamp (8 bytes)
node_type — event type (1 byte)
actor_id — actor identifier (2 bytes)
flags — reserved flags (2 bytes)
payload_ref — SHA-256 of payload (32 bytes)
frame_hash — SHA-256 of frame body (32 bytes)
Requirements
Python 3.8+
flask
reportlab
License
MIT License — free to use, modify and distribute.
Author
Giorgi Ghurtskaia — GitHub

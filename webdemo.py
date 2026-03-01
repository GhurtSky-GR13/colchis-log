import os
import tempfile
import time
import csv
import io
import secrets
from flask import (Flask, request, render_template_string,
                   redirect, url_for, flash, session, send_file)
from colchis_log import ColchisLog, HEADER_SIZE, FRAME_TOTAL, HASH_SIZE

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

HTML = '''
<!doctype html>
<html>
<head>
    <title>Colchis Log</title>
    <style>
        body { font-family: Arial; margin: 2em; background: #f5f5f5; }
        .container { max-width: 1000px; margin: auto; background: white;
                     padding: 2em; border-radius: 8px; }
        pre { background: #eee; padding: 1em; overflow: auto; border-radius: 4px; }
        .success { color: green; font-weight: bold; }
        .error { color: red; font-weight: bold; }
        button { background: #007bff; color: white; border: none;
                 padding: 0.5em 1.2em; border-radius: 4px; cursor: pointer; margin: 0.2em; }
        input[type=text] { padding: 0.5em; width: 300px; margin-right: 0.5em; }
        input[type=file] { padding: 0.3em; }
        h2 { border-bottom: 1px solid #ddd; padding-bottom: 0.3em; }
    </style>
</head>
<body>
<div class="container">
    <h1>Colchis Execution Log</h1>

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <p class="{{ category }}">{{ message }}</p>
            {% endfor %}
        {% endif %}
    {% endwith %}

    <h2>Create new log</h2>
    <form method="post" action="{{ url_for('create') }}">
        <button type="submit">Create</button>
    </form>

    <h2>Append frame</h2>
    <form method="post" action="{{ url_for('append') }}">
        <input type="text" name="data" placeholder="Payload text" required>
        <button type="submit">Append</button>
    </form>

    <h2>Upload log file</h2>
    <form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
        <input type="file" name="file" accept=".log" required>
        <button type="submit">Upload</button>
    </form>

    <h2>Actions</h2>
    <form method="post" action="{{ url_for('verify') }}" style="display:inline">
        <button type="submit">Verify</button>
    </form>
    <a href="{{ url_for('export_csv') }}">
        <button type="button">Export CSV</button>
    </a>
    {% if has_pdf %}
    <a href="{{ url_for('export_pdf') }}">
        <button type="button">Export PDF</button>
    </a>
    {% endif %}
    <a href="{{ url_for('clear') }}">
        <button type="button" style="background:#dc3545">Clear</button>
    </a>

    {% if content %}
    <h2>Log content</h2>
    <pre>{{ content }}</pre>
    {% endif %}
</div>
</body>
</html>
'''


def _read_log_content(log_path: str) -> str:
    with ColchisLog(log_path).open('rb') as log:
        frames = log.read_frames()
    if not frames:
        return "Empty log (no frames)"
    lines = [f"Total frames: {len(frames)}\n"]
    for f in frames:
        lines.append(f"--- Frame {f['frame_id']} ---")
        lines.append(f"  {f['datetime']}  Type={f['node_type']}  Actor={f['actor_id']}")
        lines.append(f"  Payload: {f['payload'][:100]}")
        lines.append(f"  Hash: {f['frame_hash'][:32]}...")
    return '\n'.join(lines)


def _get_parent_hash(log) -> bytes:
    log.f.seek(0, 2)
    size = log.f.tell()
    if size <= HEADER_SIZE:
        return b'\x00' * HASH_SIZE
    log.f.seek(-HASH_SIZE, 2)
    return log.f.read(HASH_SIZE)


@app.route('/')
def index():
    content = None
    if 'log_path' in session:
        try:
            content = _read_log_content(session['log_path'])
        except Exception as e:
            flash(f"Error: {e}", 'error')
    return render_template_string(HTML, content=content, has_pdf=HAS_PDF)


@app.route('/create', methods=['POST'])
def create():
    with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as tmp:
        log_path = tmp.name
    with ColchisLog(log_path).open('wb') as log:
        log.write_header()
    session['log_path'] = log_path
    flash("New log created", 'success')
    return redirect(url_for('index'))


@app.route('/append', methods=['POST'])
def append():
    if 'log_path' not in session:
        flash('No log created yet', 'error')
        return redirect(url_for('index'))
    data = request.form.get('data', '').strip()
    if not data:
        flash('Empty payload', 'error')
        return redirect(url_for('index'))
    try:
        log_path = session['log_path']
        with ColchisLog(log_path).open('r+b') as log:
            parent = _get_parent_hash(log)
            h = log.append_frame(parent, int(time.time()), 1, 1, 0,
                                 data.encode('utf-8'))
            log.flush()
        flash(f"Frame appended: {h.hex()[:16]}...", 'success')
    except Exception as e:
        flash(f"Error: {e}", 'error')
    return redirect(url_for('index'))


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        flash('No file', 'error')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as tmp:
        file.save(tmp.name)
        log_path = tmp.name
    session['log_path'] = log_path
    flash(f"Uploaded: {file.filename}", 'success')
    return redirect(url_for('index'))


@app.route('/verify', methods=['POST'])
def verify():
    if 'log_path' not in session:
        flash('No log loaded', 'error')
        return redirect(url_for('index'))
    try:
        with ColchisLog(session['log_path']).open('rb') as log:
            ok = log.verify()
        if ok:
            flash('Log is valid and untampered!', 'success')
        else:
            flash('Verification failed!', 'error')
    except Exception as e:
        flash(f"Error: {e}", 'error')
    return redirect(url_for('index'))


@app.route('/export_csv')
def export_csv():
    if 'log_path' not in session:
        flash('No log loaded', 'error')
        return redirect(url_for('index'))
    try:
        with ColchisLog(session['log_path']).open('rb') as log:
            frames = log.read_frames()
        output = io.StringIO()
        fieldnames = ['frame_id', 'parent_hash', 'timestamp', 'datetime',
                      'node_type', 'actor_id', 'flags',
                      'payload_ref', 'frame_hash', 'payload']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(frames)
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='colchis_export.csv'
        )
    except Exception as e:
        flash(f"Export error: {e}", 'error')
        return redirect(url_for('index'))


@app.route('/export_pdf')
def export_pdf():
    if not HAS_PDF:
        flash('PDF not available', 'error')
        return redirect(url_for('index'))
    if 'log_path' not in session:
        flash('No log loaded', 'error')
        return redirect(url_for('index'))
    try:
        with ColchisLog(session['log_path']).open('rb') as log:
            frames = log.read_frames()
        output = io.BytesIO()
        c = canvas.Canvas(output, pagesize=letter)
        width, height = letter
        y = height - 40
        c.setFont("Helvetica", 8)
        c.drawString(40, y, f"Colchis Execution Log  |  Frames: {len(frames)}")
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
        output.seek(0)
        return send_file(output, mimetype='application/pdf',
                         as_attachment=True,
                         download_name='colchis_export.pdf')
    except Exception as e:
        flash(f"Export error: {e}", 'error')
        return redirect(url_for('index'))


@app.route('/clear')
def clear():
    session.clear()
    flash('Session cleared', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)

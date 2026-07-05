"""
Internal file-distribution service.

Serves documents from a fixed content directory over HTTP. A security review
flagged that one of the download-style endpoints can be abused to read files
outside the intended content directory. Your job is to fix the vulnerability
while keeping all legitimate functionality working.
"""
import os

from flask import Flask, request, send_file, abort, jsonify

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/download")
def download():
    """Download a document from the content directory by name."""
    name = request.args.get("name", "")
    if not name:
        abort(400)
    path = os.path.join(BASE_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


@app.route("/preview")
def preview():
    """Preview one of a small set of allow-listed documents."""
    name = request.args.get("name", "")
    allowed = {"readme.txt", "notes.txt", "report.txt"}
    if name not in allowed:
        abort(403)
    return send_file(os.path.join(BASE_DIR, name))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)

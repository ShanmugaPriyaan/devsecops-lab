"""Deliberately vulnerable Flask app for the DevSecOps lab. Do not deploy."""
import base64
import ipaddress
import pickle
import sqlite3
import subprocess


from flask import Flask, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-12345"  # FLAW: hard-coded secret


def db():
    conn = sqlite3.connect("lab.db")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
    return conn


@app.route("/")
def index():
    return (
        "<h1>Patient lookup (lab)</h1>"
        '<a href="/user?name=bob">Find user</a> | '
        '<a href="/ping?host=127.0.0.1">Ping</a>'
    )


@app.route("/user")
def user():
    name = request.args.get("name", "")
    rows = db().execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    return {"rows": rows}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)  # allow-list: only a valid IP address gets through
    except ValueError:
        return {"error": "invalid IP address"}, 400
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return {"output": result.stdout}


@app.route("/restore", methods=["POST"])
def restore():
    # FLAW: insecure deserialisation of user-supplied data
    data = pickle.loads(base64.b64decode(request.data))
    return {"restored": str(data)}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)  # FLAW: debugger exposed

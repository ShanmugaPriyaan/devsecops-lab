"""Deliberately vulnerable Flask app for the DevSecOps lab. Do not deploy."""
import ipaddress
import os
import sqlite3
import subprocess


from flask import Flask, request

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")  # injected at runtime, never stored in code


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
    )gi


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
    data = request.get_json(silent=True)  # JSON can only ever produce data, never code
    if data is None:
        return {"error": "expected a JSON body"}, 400
    return {"restored": data}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # debug is off by default

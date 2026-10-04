import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # Planted problem: SQL built by joining user input
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cur.fetchall())

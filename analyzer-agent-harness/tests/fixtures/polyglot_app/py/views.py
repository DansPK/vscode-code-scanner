import pickle
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load():
    return str(pickle.loads(request.data))


@app.route("/run")
def run():
    return subprocess.check_output(request.args["cmd"], shell=True)

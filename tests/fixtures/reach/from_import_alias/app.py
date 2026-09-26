from yaml import full_load as fl
from flask import Flask

app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload():
    return str(fl(b"k: v"))

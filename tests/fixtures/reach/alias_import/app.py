import yaml as y
from flask import Flask

app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload():
    return str(y.full_load(b"k: v"))

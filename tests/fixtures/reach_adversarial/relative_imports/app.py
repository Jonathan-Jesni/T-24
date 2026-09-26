from svc.loader import load
from flask import Flask

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    return str(load(b"k: v"))

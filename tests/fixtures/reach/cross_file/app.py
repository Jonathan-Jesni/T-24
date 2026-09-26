import yaml
from flask import Flask

app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload():
    from config import load_settings
    return str(load_settings(b"k: v"))

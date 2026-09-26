from flask import Flask
import yaml

app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload():
    data = b"key: value"
    return str(yaml.full_load(data))

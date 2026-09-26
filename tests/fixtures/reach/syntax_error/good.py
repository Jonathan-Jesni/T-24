import yaml
from flask import Flask

app = Flask(__name__)

@app.route("/upload")
def upload():
    return str(yaml.full_load(b"k: v"))

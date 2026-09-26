import yaml
from flask import Flask

app = Flask(__name__)


def run(fn, raw):
    return fn(raw)


@app.route("/upload", methods=["POST"])
def upload():
    return str(run(yaml.full_load, b"k: v"))

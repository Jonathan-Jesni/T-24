import yaml
from flask import Flask

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    from safe import parse
    return str(parse(b"k: v"))

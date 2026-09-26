import yaml
from flask import Flask

app = Flask(__name__)


class Loader:
    def load(self, raw):
        return yaml.full_load(raw)


@app.route("/upload", methods=["POST"])
def upload():
    return str(Loader().load(b"k: v"))

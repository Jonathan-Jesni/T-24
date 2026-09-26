import yaml
import importlib
from flask import Flask

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    # Dynamic access patterns — all should produce uncertain, not a hop
    getattr(yaml, "full_" + "load")("x")          # dynamic attribute
    importlib.import_module("yaml")                # importlib
    __import__("yaml")                             # __import__
    mod = yaml                                     # module passed as value
    return "ok"

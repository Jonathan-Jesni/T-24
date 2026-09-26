import yaml
from flask import Flask

app = Flask(__name__)

@app.route("/safe")
def safe():
    return "ok"

def hidden():
    # This function is never called from any entry point
    return str(yaml.full_load(b"k: v"))

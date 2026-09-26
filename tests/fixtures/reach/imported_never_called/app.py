import yaml
from flask import Flask

app = Flask(__name__)

@app.route("/safe")
def safe():
    # yaml is imported but full_load is never called
    return "ok"

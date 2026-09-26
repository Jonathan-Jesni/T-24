import yaml
from flask import Flask

app = Flask(__name__)

@app.route("/load")
def load():
    # FullLoader referenced as Loader= argument — not a direct call but a reference
    return str(yaml.load(b"k: v", Loader=yaml.FullLoader))

"""route -> Loader().load(x) -> yaml.full_load

Evidence chain must start at the route and name functions correctly:
  app.py:<route line>  function="upload"  call="Loader().load"
  app.py:<load line>   function="Loader.load"  call="yaml.full_load"
"""
import yaml
from flask import Flask

app = Flask(__name__)


class Loader:
    def load(self, raw):
        return yaml.full_load(raw)


@app.route("/upload", methods=["POST"])
def upload():
    return str(Loader().load(b"k: v"))

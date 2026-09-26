"""route -> S().go() -> self._p() -> yaml.full_load  (3-hop chain)

Evidence chain must name functions correctly:
  hop 0: file=app.py  function="index"     call contains "S().go"
  hop 1: file=app.py  function="S.go"      call contains "self._p"
  hop 2: file=app.py  function="S._p"      call contains "yaml.full_load"
"""
import yaml
from flask import Flask

app = Flask(__name__)


class S:
    def go(self):
        self._p()

    def _p(self):
        yaml.full_load("x: 1")


@app.route("/")
def index():
    S().go()
    return "ok"

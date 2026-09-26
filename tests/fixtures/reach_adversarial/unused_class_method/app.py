"""Unused class — never instantiated, never called.

The class Unused is defined but the route never references it.
yaml.full_load inside Unused.load must NOT be reached.
"""
import yaml
from flask import Flask

app = Flask(__name__)


class Unused:
    def load(self, raw):
        return yaml.full_load(raw)  # must NOT be reached


@app.route("/ping")
def ping():
    return "pong"  # never touches yaml

"""Module object passed as value — neither reached nor uncertain currently.

def use(m): return m.full_load(x)
route calls use(yaml)

The bare module name 'yaml' is passed as an argument.
Any load of the bare module name that is NOT immediately followed by
attribute access must set uncertain=True.
"""
import yaml
from flask import Flask

app = Flask(__name__)


def use(m):
    return m.full_load("data")


@app.route("/upload", methods=["POST"])
def upload():
    return str(use(yaml))

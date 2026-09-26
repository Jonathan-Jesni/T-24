import yaml
from flask import Flask

app = Flask(__name__)


def a():
    return str(yaml.full_load(b"k: v"))


app.add_url_rule("/a", view_func=a)

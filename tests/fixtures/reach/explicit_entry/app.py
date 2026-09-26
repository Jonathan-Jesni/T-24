import yaml
from flask import Flask

app = Flask(__name__)

def not_a_route():
    # This is NOT decorated — explicit entry point needed
    return str(yaml.full_load(b"k: v"))

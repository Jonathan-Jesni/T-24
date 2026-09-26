import yaml


def parse(raw):
    # This file is NEVER imported by app.py
    return yaml.full_load(raw)

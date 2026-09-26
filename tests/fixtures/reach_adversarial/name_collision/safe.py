import yaml


def parse(raw):
    return yaml.safe_load(raw)

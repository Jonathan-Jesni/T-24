import yaml


def parse(raw):
    return yaml.full_load(raw)

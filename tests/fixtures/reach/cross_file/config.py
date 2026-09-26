import yaml

def load_settings(raw: bytes) -> dict:
    return yaml.full_load(raw)

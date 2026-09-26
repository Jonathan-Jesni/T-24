import yaml

def load_settings(raw: bytes) -> dict:
    """Load settings from a YAML byte string. Called from app.upload_config."""
    return yaml.safe_load(raw)

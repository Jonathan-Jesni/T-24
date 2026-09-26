"""
Regression test for CVE-2020-14343 — PyYAML arbitrary code execution via
yaml.full_load / FullLoader.

Evidence from dossier.json:
  demo_product/app.py:14  upload_config -> config.load_settings
  demo_product/config.py:5 load_settings -> yaml.full_load

The exploit payload uses !!python/object/new tags that cause yaml.full_load
to execute arbitrary Python expressions. On unfixed code the response body
contains "EXPLOITED-42".

The test FAILS on current code (yaml.full_load is still in use).
After the fix (yaml.safe_load + HTTP 400 guard) the test PASSES.
"""
import sys
import os

# Allow importing app from demo_product without installing it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as demo_app
from werkzeug.test import Client


# Exact payload from the CVE-2020-14343 advisory brief.
# Uses !!python/object/new to invoke eval("'EXPLOITED-' + str(6*7)") = "EXPLOITED-42".
EXPLOIT_PAYLOAD = (
    b"!!python/object/new:tuple "
    b"[!!python/object/new:map "
    b"[!!python/name:eval , "
    b'["\'EXPLOITED-\' + str(6*7)"]]]'
)


def test_cve_2020_14343_exploit_blocked():
    """
    POST the YAML RCE payload to /upload-config.
    The response must NOT contain the string "EXPLOITED-42".
    On unfixed code (yaml.full_load) this test FAILS because the eval runs
    and the string "EXPLOITED-42" appears in the response.
    After the fix (yaml.safe_load + HTTP 400) this test PASSES.
    """
    client = Client(demo_app.app)
    response = client.post(
        "/upload-config",
        data=EXPLOIT_PAYLOAD,
        content_type="application/octet-stream",
    )
    body = response.data.decode("utf-8", errors="replace")
    assert "EXPLOITED-42" not in body, (
        f"CVE-2020-14343: RCE payload was executed — yaml.full_load is still in use. "
        f"Response body: {body!r}"
    )

# Prebuilt wheel for Windows

PyYAML 5.3.1 has no official Windows wheel for Python 3.11, so `pip` tries to compile it and fails without the Microsoft C++ Build Tools.
This wheel was built from the official PyYAML 5.3.1 source distribution on Python 3.11 (64-bit Windows). Install it before the demo requirements:

```
.venv\Scripts\python -m pip install demo_product\wheels\pyyaml-5.3.1-cp311-cp311-win_amd64.whl
.venv\Scripts\python -m pip install -e ".[dev]" -r demo_product\requirements.txt
```

This is the intentionally vulnerable version used by the demo (CVE-2020-14343). Never use it outside this demo.

# fake_pkg_caller: a library where an internal function calls the vulnerable one.
# internal_func calls build_proxies (the vulnerable symbol).

def build_proxies(url, proxies):
    """The vulnerable function."""
    return proxies


def internal_func(url):
    """Calls build_proxies internally — not exposed to callers."""
    return build_proxies(url, {})

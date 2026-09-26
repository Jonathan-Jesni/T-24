# fake_pkg_def_only: a library where the vulnerable symbol is only defined,
# never called internally.

def rebuild_proxies(result, proxies):
    """The vulnerable function — only definition, no internal callers."""
    if proxies:
        result.headers.update(proxies)
    return result

# fake_pkg_builtins_eval: a library with a function named "eval" that uses
# builtins.eval — this must NOT be flagged as an internal caller of "eval".

def process(expr, env):
    """Calls builtins.eval — receiver is 'builtins', should be ignored."""
    import builtins
    return builtins.eval(expr, env)


def eval(expr, env=None):
    """The vulnerable symbol — this is the definition, not a caller."""
    return process(expr, env)

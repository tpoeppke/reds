from redsmaster import exc

def deny_write_hook(*args, **kwargs):
    raise exc.AbortError("You are not allowed to write to this repository!")
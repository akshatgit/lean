import vendor


def foo(x):
    # Repository code that shares only its NAME with the declared `foo`.  It does not
    # visibly touch the database (so 2c alone would not catch it), but it is not provably
    # effect-free either: a bare declaration must not silently vouch for it.
    vendor.transmit(x)
    return x

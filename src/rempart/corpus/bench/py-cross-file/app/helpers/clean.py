def only_digits(value):
    return int(value)


def pick_column(name):
    if name not in ("name", "email", "created"):
        raise ValueError("bad column")
    return name

"""Scan target names: a container image reference, or a file or project name."""


def image_repository(target: str) -> str:
    """`ghcr.io/org/app:1.2@sha256:…` -> `ghcr.io/org/app`: the name without tag or digest.

    A colon only starts a tag after the last slash, so `localhost:5000/app` keeps its port.
    """
    name = target.split("@", 1)[0]
    last_slash = name.rfind("/")
    colon = name.rfind(":")
    return name[:colon] if colon > last_slash else name

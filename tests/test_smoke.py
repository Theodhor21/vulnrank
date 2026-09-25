import vulnrank


def test_package_exposes_version() -> None:
    assert isinstance(vulnrank.__version__, str)
    assert vulnrank.__version__

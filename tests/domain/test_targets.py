import pytest

from vulnrank.domain.targets import image_repository


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("nginx:1.19", "nginx"),
        ("my-app:abc123", "my-app"),
        ("ghcr.io/org/app:1.2", "ghcr.io/org/app"),
        ("localhost:5000/app:1.0", "localhost:5000/app"),
        ("localhost:5000/app", "localhost:5000/app"),
        ("app@sha256:0123abcd", "app"),
        ("ghcr.io/org/app:1.2@sha256:0123abcd", "ghcr.io/org/app"),
        ("bkimminich/juice-shop", "bkimminich/juice-shop"),
        ("scan.json", "scan.json"),
    ],
)
def test_image_repository_drops_tag_and_digest(target: str, expected: str) -> None:
    assert image_repository(target) == expected

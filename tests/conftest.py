import pytest


@pytest.fixture
def make_symlink():
    """Create a symlink, or skip where the OS denies that capability."""
    def create(link, target) -> None:
        try:
            link.symlink_to(target)
        except OSError as exc:
            pytest.skip(f"symlinks are unavailable in this environment: {exc}")

    return create

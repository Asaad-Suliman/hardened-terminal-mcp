import pytest


@pytest.fixture
def scratch_dir(tmp_path):
    return tmp_path

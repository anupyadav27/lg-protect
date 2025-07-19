import pytest

@pytest.fixture
def sample_fixture():
    return "sample data"

def test_sample_fixture(sample_fixture):
    assert sample_fixture == "sample data"
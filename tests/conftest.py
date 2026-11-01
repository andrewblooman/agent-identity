import pytest
from fastapi.testclient import TestClient

from agent_identity.config import Settings
from agent_identity.main import create_app


@pytest.fixture
def settings(tmp_path):
    return Settings(_env_file=None, database_path=tmp_path / "test.sqlite3", aws_profile=None)


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings))

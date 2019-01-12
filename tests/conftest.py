import pytest
import os
import uuid
import platform


@pytest.fixture(scope='session', autouse=True)
def setup_env():
    """Setup AWS mock environment before tests, then revert all changes"""

    # Launch localstack environment
    if platform.system() == "Darwin":
        os.system('TMPDIR=/private$TMPDIR docker-compose up -d')
    else:
        os.system('docker-compose up -d')

    yield

    # Teardown
    # Turn down localstack environment
    if platform.system() == "Darwin":
        os.system('TMPDIR=/private$TMPDIR docker-compose down')
    else:
        os.system('docker-compose down')

    return


@pytest.fixture()
def data_user_record():
    """Single user record to insert into DB"""
    return {"test@test.com", "U122345"}, str(uuid.uuid4())

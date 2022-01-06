import os

import boto3
import pytest
from moto import mock_sts

import aws_account


@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "12345"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "45723482038"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "eu-central-1"


@pytest.fixture(scope="function")
def sts(aws_credentials):
    with mock_sts():
        yield boto3.client("sts")


@pytest.fixture(scope="function")
def iam(aws_credentials):
    with mock_sts():
        yield boto3.client("iam")


def test_caller_identity(sts, iam):
    # sts is a fixture defined above that yields a boto3 sts client.
    aws_account.cli.main()
    caller_identity = sts.get_caller_identity()
    assert caller_identity["Account"] == "testing"
    assert caller_identity["Arn"].startswith("arn:aws:iam::testing:")

from unittest import mock
from unittest.mock import patch

from aws_account.cli import AWSAccount, AWSIdentity, _get_access_token


def test_awsaccount_basic():
    account = AWSAccount("id", "name", "email@email.com")
    assert account.id == "id"
    assert account.name == "name"
    assert account.email == "email@email.com"


def test_awsidentity_with_iamuser():
    arn = "arn='arn:aws:iam::11122233334444:user/superadmin'"
    account = "11122233334444"
    user_id = "CR4ZEACOVAIDASXAYEZNC"

    identity = AWSIdentity(user_id=user_id, account=account, arn=arn)

    assert identity.is_iam()
    assert identity.is_assumed_role() is False
    assert identity.type == AWSIdentity.CallerIdentityType.IAM


@patch(
    "builtins.open",
    new_callable=mock.mock_open,
    read_data='{"startUrl": "https://a123.awsapps.com/start", '
    + '"region": "eu-central-1", "accessToken": "pzFA3BZ0s7Q4xHGv", '
    + '"expiresAt": "2021-11-09T02:58:40Z"}',
)
@patch(
    "os.listdir",
    return_value=[
        "aws-toolkit-jetbrains-client-id-eu-central-9.json",
        "09042c3fff60f06bad40477bd3d1fc628034320e.json",
        "botocore-client-id-eu-central-1.json",
    ],
)
@patch("os.path.expanduser", return_value="/Users/test/.aws/sso/cache")
def test_get_access_token(expanduser, listdir, builtins_open):
    class FileValidator(object):
        def __init__(
            self, validator
        ):  # validator=function taking a single argument and returns a bool.
            self.validator = validator

        def __eq__(self, other):
            return bool(self.validator(other))

        token = _get_access_token()
        builtins_open.assert_called_with(
            "/Users/test/.aws/sso/cache/09042c3fff60f06bad40477bd3d1fc628034320e.json",
            "r",
        )
        assert token == "pzFA3BZ0s7Q4xHGv"

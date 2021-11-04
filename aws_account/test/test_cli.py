import pytest

from aws_account.cli import *

def test_awsaccount_basic():
    account = AWSAccount("id", "name", "email@email.com")
    assert account.id == "id"
    assert account.name == "name"
    assert account.email == "email@email.com"

def test_awsidentity_with_iamuser():
    arn = "arn='arn:aws:iam::11122233334444:user/superadmin'"
    account = '11122233334444'
    user_id = 'CR4ZEACOVAIDASXAYEZNC'

    identity = AWSIdentity(user_id=user_id, account=account, arn=arn)

    assert identity.is_iam()
    assert identity.is_assumed_role() == False
    assert identity.type == AWSIdentity.Type.IAM




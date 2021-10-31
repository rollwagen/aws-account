import logging
from logging import Logger, Formatter

import os

from typing import NamedTuple
from enum import Enum

import click
import json

from colorama import Fore

import botocore
import botocore.session
import botocore.exceptions

__version__ = "0.1"

log: Logger = None

class AWSAccount(NamedTuple):
    id: str
    name: str
    email: str

class AWSIdentity(NamedTuple):
    class Type(Enum):
        """An identity can have one of the following types:
            arn:aws:iam::123456789012:user/Alice
            arn:aws:sts::123456789012:assumed-role/my-role-name/my-role-session-name
            arn:aws:sts::123456789012:federated-user/my-federated-user-name
        For further details see AWS documentation at
            <https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html>
        """

        IAM = 1
        ASSUMED_ROLE = 2
        FEDERATED_USER = 3

    user_id: str
    account: str
    arn: str

    _type_mapping = {
        "user": Type.IAM,
        "assumed-role": Type.ASSUMED_ROLE,
        "federated-user": Type.FEDERATED_USER,
    }

    @property
    def account_name(self):
        return self.account_name

    @property
    def type(self) -> int:
        # type = self.arn.split(":")[2]
        type = self.arn.split(":")[5].split("/")[0]
        return self._type_mapping[type]

    @property
    def user_name(self):
        return self.arn.split(":")[-1].split("/")[-1]

    def is_iam(self):
        return self.type == self.Type.IAM

    def is_assumed_role(self):
        return self.type == self.Type.ASSUMED_ROLE


@click.command()
@click.option("--version", is_flag=True, help="Print version number.")
def main(version: bool):
    if version:
        print(f"Version: {__version__}")
        exit(0)

    try:
        session = botocore.session.get_session()
        caller_identity = session.create_client("sts").get_caller_identity()
        log.debug(f"get_call_identity() response: {caller_identity}")
        identity = AWSIdentity(
            account=caller_identity["Account"],
            user_id=caller_identity["UserId"],
            arn=caller_identity["Arn"],
        )

        log.debug(f"{identity=}")

        if identity.is_assumed_role():
            token = _get_access_token()
            account_list = session.create_client("sso").list_accounts(accessToken=token)["accountList"]
            account_item = next(a for a in account_list if a["accountId"] == identity.account)
            log.debug(f'{account_item=}')
            account = AWSAccount(id=account_item["accountId"], name=account_item["accountName"], email=account_item["emailAddress"])
        else:
            account = None

    except Exception as exception:
        log.error(exception)
        exit(1)

    _print_identity_info(identity=identity, account=account)


def _get_access_token() -> str:
    # aws sso  list-accounts --access-token $(cat $(ls -1d ~/.aws/sso/cache/* | grep -v botocore) |  jq -r "{accessToken} | .[]")
    aws_sso_cache_dir = os.path.expanduser("~/.aws/sso/cache")
    try:
        cache_file = [f for f in os.listdir(aws_sso_cache_dir) if not f.startswith("botocore-")][0]
        cache_filepath = f'{aws_sso_cache_dir}/{cache_file}'
        with open(cache_filepath, "r") as token_cache_file:
            token_json = json.loads(token_cache_file.read())

        access_token = token_json["accessToken"]
        log.debug(f'accessToken = {access_token[0:9]}...')
        return access_token
    except Exception as exception:
        log.error(exception)

    return None


def _print_identity_info(identity: AWSIdentity, account: AWSAccount=None) -> None:
    COLOR_KEY = Fore.BLUE
    COLOR_VALUE = Fore.GREEN
    WIDTH_VALUE = 15

    def _color(name: str, value: str) -> str:
        return f"{COLOR_KEY}{name:<{WIDTH_VALUE}}{COLOR_VALUE}{value}"

    print(_color("Identity:", identity.user_name))
    print(_color("Account:", identity.account))
    _type_key_str = "Type:"
    if identity.type is AWSIdentity.Type.IAM:
        print(_color(_type_key_str, "IAM User"))
    elif identity.type is AWSIdentity.Type.ASSUMED_ROLE:
        if account:
            print(_color("Account Name:", account.name))
        print(_color(_type_key_str, "Assumed Role (sts)"))



def _init_logger() -> Logger:
    class CustomFormatter(Formatter):
        grey = "\x1b[38;21m"
        yellow = "\x1b[33;21m"
        red = "\x1b[31;21m"
        bold_red = "\x1b[31;1m"
        reset = "\x1b[0m"
        format = (
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            + " (%(filename)s:%(lineno)d)"
        )

        FORMATS = {
            logging.DEBUG: grey + format + reset,
            logging.INFO: grey + format + reset,
            logging.WARNING: yellow + format + reset,
            logging.ERROR: red + format + reset,
            logging.CRITICAL: bold_red + format + reset,
        }

        def format(self, record):
            log_fmt = self.FORMATS.get(record.levelno)
            formatter = logging.Formatter(log_fmt)
            return formatter.format(record)

    logger = logging.getLogger("aws-account")
    logger.setLevel(logging.DEBUG)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    return logger


if __name__ == "__main__":
    log = _init_logger()
    main()

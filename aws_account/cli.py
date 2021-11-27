import importlib.metadata
import json
import logging
import os
from enum import Enum
from logging import Formatter, Logger
from typing import NamedTuple

import botocore
import botocore.exceptions
import botocore.session
import click
from colorama import Fore

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
        _is_assumed_role = self.type == self.Type.ASSUMED_ROLE
        return _is_assumed_role


@click.command()
@click.option("--version", is_flag=True, help="Print version number.")
@click.option("--debug", is_flag=True, help="Enable debug output.")
def main(version: bool, debug: bool):
    """A tool to print out AWS account and identity information to verify
    which account/organization is currently in use."""
    global log
    log = _init_logger(debug)
    if version:
        print(f'Version: {importlib.metadata.version("aws-account")}')
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

        account = None
        if identity.is_assumed_role():
            log.debug("getting access token")
            token = _get_access_token()
            account_list = session.create_client("sso").list_accounts(
                accessToken=token
            )["accountList"]
            account_item = next(
                a for a in account_list if a["accountId"] == identity.account
            )
            log.debug(f"{account_item=}")
            account = AWSAccount(
                id=account_item["accountId"],
                name=account_item["accountName"],
                email=account_item["emailAddress"],
            )

    except Exception as exception:
        log.error(exception)
        exit(1)

    _print_identity_info(identity=identity, account=account)


def _get_access_token() -> str:
    global log
    if not log:
        log = _init_logger(debug_level=False)

    aws_sso_cache_dir = os.path.expanduser("~/.aws/sso/cache")
    log.debug(f"_get_access_token: {aws_sso_cache_dir=}")

    try:
        cache_file = [f for f in os.listdir(aws_sso_cache_dir) if f[0].isdigit()][0]
        cache_filepath = f"{aws_sso_cache_dir}/{cache_file}"
        log.debug(f"{cache_filepath=}")
        with open(cache_filepath, "r") as token_cache_file:
            token_json = json.loads(token_cache_file.read())

        access_token = token_json["accessToken"]
        log.debug(f"accessToken = {access_token[0:9]}...")
        return access_token
    except Exception as exception:
        log.error(exception)

    return None


def _print_identity_info(identity: AWSIdentity, account: AWSAccount = None) -> None:
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


def _init_logger(debug_level: bool = False) -> Logger:
    class CustomFormatter(Formatter):
        grey = "\x1b[38;21m"
        yellow = "\x1b[33;21m"
        red = "\x1b[31;21m"
        bold_red = "\x1b[31;1m"
        reset = "\x1b[0m"
        if debug_level:
            format = (
                "%(asctime)s - %(name)s - %(levelname)s"
                + " - %(message)s (%(filename)s:%(lineno)d)"
            )
        else:
            format = "%(levelname)s - %(message)s"

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
    if debug_level:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARN)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    return logger


if __name__ == "__main__":
    main()

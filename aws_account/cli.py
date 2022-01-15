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

log: Logger = None  # type: ignore


class AWSAccount(NamedTuple):
    id: str
    name: str
    email: str


class AWSIdentity(NamedTuple):
    user_id: str
    account: str
    arn: str

    class CallerIdentityType(Enum):  # type: ignore
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

    type_mapping: dict = {
        "user": CallerIdentityType.IAM,
        "assumed-role": CallerIdentityType.ASSUMED_ROLE,
        "federated-user": CallerIdentityType.FEDERATED_USER,
    }

    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
    iam_unique_prefixes: dict = {
        "ABIA": "AWS STS service bearer token",
        "ACCA": "Context-specific credential",
        "AGPA": "User group",
        "AIDA": "IAM user",
        "AIPA": "Amazon EC2 instance profile",
        "AKIA": "Access key",
        "ANPA": "Managed policy",
        "ANVA": "Version in a managed policy",
        "APKA": "Public key",
        "AROA": "Role",
        "ASCA": "Certificate",
        "ASIA": "Temporary (AWS STS) access key",
    }

    @property
    def account_name(self):
        return self.account_name

    @property
    def type(self) -> CallerIdentityType:
        # type = self.arn.split(":")[2]
        type = self.arn.split(":")[5].split("/")[0]
        return self.type_mapping[type]

    @property
    def user_name(self):
        return self.arn.split(":")[-1].split("/")[-1]

    def is_iam(self):
        return self.type == self.CallerIdentityType.IAM

    def is_assumed_role(self):
        _is_assumed_role = self.type == self.CallerIdentityType.ASSUMED_ROLE
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
        log.debug(f"{session.get_credentials().access_key=}")
        sts = session.create_client("sts")
        caller_identity = sts.get_caller_identity()  # type: ignore
        log.debug(f"get_call_identity() response: {caller_identity}")
        identity = AWSIdentity(
            account=caller_identity["Account"],
            user_id=caller_identity["UserId"],
            arn=caller_identity["Arn"],
        )

        log.debug(f"{identity=}")

        account = None
        if identity.is_assumed_role():
            token = _get_access_token()
            account_list = session.create_client(
                "sso").list_accounts(  # type: ignore
                    accessToken=token)["accountList"]
            account_item = next(a for a in account_list
                                if a["accountId"] == identity.account)
            log.debug(f"{account_item=}")
            account = AWSAccount(
                id=account_item["accountId"],
                name=account_item["accountName"],
                email=account_item["emailAddress"],
            )
        elif identity.is_iam():
            iam = session.create_client("iam")
            account_alias = iam.list_account_aliases()["AccountAliases"][0]
            account = AWSAccount(id=identity.account,
                                 name=account_alias,
                                 email="")

    except Exception as exception:
        log.error(exception)
        exit(1)

    _print_identity_info(identity=identity, account=account)


def _get_access_token() -> str:
    global log
    if not log:
        log = _init_logger(debug_level=False)
    log.debug("_get_access_token() function")

    aws_sso_cache_dir = os.path.expanduser("~/.aws/sso/cache")
    log.debug(f"_get_access_token: {aws_sso_cache_dir=}")

    try:
        cache_file = [
            f for f in os.listdir(aws_sso_cache_dir) if f[0].isdigit()
        ][0]
        cache_filepath = f"{aws_sso_cache_dir}/{cache_file}"
        log.debug(f"{cache_filepath=}")
        with open(cache_filepath, "r") as token_cache_file:
            token_json = json.loads(token_cache_file.read())

        access_token = token_json["accessToken"]
        log.debug(f"accessToken = {access_token[0:9]}...")
        return access_token
    except Exception as exception:
        log.error(exception)

    return ""


def _print_identity_info(identity: AWSIdentity,
                         account: AWSAccount = None) -> None:
    COLOR_KEY = Fore.BLUE
    COLOR_VALUE = Fore.GREEN
    WIDTH_VALUE = 15

    def _color(name: str, value: str) -> str:
        return f"{COLOR_KEY}{name:<{WIDTH_VALUE}}{COLOR_VALUE}{value}"

    print(_color("Identity:", identity.user_name))
    print(_color("Account:", f"{identity.account} ({account.name})"))
    _type_key_str = "Type:"
    if identity.type is AWSIdentity.CallerIdentityType.IAM:
        print(_color(_type_key_str, "IAM User"))
    elif identity.type is AWSIdentity.CallerIdentityType.ASSUMED_ROLE:
        print(_color(_type_key_str, "Assumed Role (sts)"))


def _init_logger(debug_level: bool = False) -> Logger:

    class CustomFormatter(Formatter):
        grey = "\x1b[38;21m"
        yellow = "\x1b[33;21m"
        red = "\x1b[31;21m"
        bold_red = "\x1b[31;1m"
        reset = "\x1b[0m"
        output_format: str = ""
        if debug_level:
            output_format = ("%(asctime)s - %(name)s - %(levelname)s" +
                             " - %(message)s (%(filename)s:%(lineno)d)")
        else:
            output_format = "%(levelname)s - %(message)s"

        FORMATS = {
            logging.DEBUG: grey + output_format + reset,
            logging.INFO: grey + output_format + reset,
            logging.WARNING: yellow + output_format + reset,
            logging.ERROR: red + output_format + reset,
            logging.CRITICAL: bold_red + output_format + reset,
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

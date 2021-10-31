import logging
from logging import Logger, Formatter

from typing import NamedTuple
from enum import Enum

import click

import botocore
import botocore.session
import botocore.exceptions

__version__ = "0.1"


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
    account: int
    arn: str


@click.command()
@click.option("--version", is_flag=True, help="Print version number.")
def main(version: bool):
    log = _get_logger()
    if version:
        print(f"Version: {__version__}")
        exit(0)

    try:
        session = botocore.session.get_session()
        caller_identity = session.create_client("sts").get_caller_identity()
        log.debug(f"get_call_identity() response: {caller_identity}")
        identity_info = AWSIdentity(
            account=caller_identity["Account"],
            user_id=caller_identity["UserId"],
            arn=caller_identity["Arn"],
        )
        log.debug(f"{identity_info=}")
    except Exception as exception:
        log.error(exception)


def _get_logger() -> Logger:
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
    main()

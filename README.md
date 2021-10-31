# aws-account

A tool to print out AWS account and identity information to verify
which account/organization is currently in use.

Whereas `aws sts get-caller-identity` only prints the account number,
_aws-account_ resovled the account id to the actual account name via calling
`aws sso list-accounts --access-token ...` (i.e. the python boto3 equivalent)
when the identity is an 'assumed role' with a SSO login.

This is meant to be especially helpful when working with multiple AWS accounts
e.g. within an AWS Organization and/or across organizations.

## Install

Recommended to install via [pipx](https://github.com/pypa/pipx)

```sh
pipx install aws-account
```

## Usage

```sh
Usage: aws-account [OPTIONS]

  A tool to print out AWS account and identity information to verify which
  account/organization is currently in use.

Options:
  --version  Print version number.
  --debug    Enable debug output.
  --help     Show this message and exit
```

Example output:
![Screenshot output](/img/screenshot-aws-account.png)

## Note

This is a early beta|draft version; use with caution and (if in doubt)
verify with aws' offical cli call `aws sts get-caller-identity`.

from setuptools import setup

setup(
    name="aws-account",
    version="0.1",
    py_modules=["aws-account"],
    install_requires=["click", "botocore", "colorama"],
    entry_points={"console_scripts": ["aws-account=aws-account:main"]},
)

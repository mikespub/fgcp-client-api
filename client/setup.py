# coding: utf-8

import sys
from setuptools import setup, find_packages

NAME = "swagger_client"
VERSION = "1.0.0"



# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

REQUIRES = ["urllib3 >= 1.15", "six >= 1.10", "certifi", "python-dateutil"]

setup(
    name=NAME,
    version=VERSION,
    description="FGCP Demo REST API",
    author_email="",
    url="",
    keywords=["Swagger", "FGCP Demo REST API"],
    install_requires=REQUIRES,
    packages=find_packages(),
    include_package_data=True,
    long_description="""\
    Demo REST API for the Fujitsu Cloud IaaS Trusted Public S5 (TPS5) aka Fujitsu Global Cloud Platform (FGCP) - generated from SwaggerHub
    """
)


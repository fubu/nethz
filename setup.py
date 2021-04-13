#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name="nethz",
    version="1.1",
    author="Fubu",
    description=("Library to easily access ETH ldap"),
    packages=find_packages(),
    install_requires=['ldap3>=0.9.8.2']
)

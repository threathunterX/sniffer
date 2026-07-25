#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='nebula_sniffer',
    version='2.15.0',
    description=('nebula sniffer extracts nebula interested'
                 ' information from http/https traffic'),
    author='Wen Lu',
    author_email='luwen@threathunter.cn',
    url='https://www.threathunter.cn',
    packages=find_packages(exclude=["test"]),
    package_data={'': ['nebula_sniffer/*.conf']},
    install_requires=["Click"],
    include_package_data=True,
    entry_points='''
        [console_scripts]
        sniffer_cli=nebula_sniffer.sniffer_cli:cli
    ''',
)

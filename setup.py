#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup
import pyh3c.pyh3c

setup(name='pyh3c',
      version=pyh3c.pyh3c.__version__,
      description='A program for passing h3c authentication in SYSU east campus.',
      author='houqp',
      author_email='qingping.hou@gmail.com',
      url='https://github.com/houqp/pyh3c',
      download_url='https://github.com/houqp/pyh3c',
      license='GPL',
      packages=['pyh3c', 'pyh3c/plugins'],
      scripts=['scripts/pyh3c'],
      )

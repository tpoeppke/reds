#!/usr/bin/env python
# -*- coding: utf-8 -*-

import setuptools
import os
import sys

# Add the sources to get the version number
basedir = os.path.abspath(os.path.dirname(sys.argv[0]))
sys.path.insert(0, os.path.join(basedir, 'src'))
import redsmaster

setuptools.setup(name='redsmaster',
                 version=redsmaster.VERSION,
                 description='Revision controlled document storage for cloud services',
                 author='Tobias Pöppke',
                 author_email='t.poeppke@gmx.de',
                 url='--',
                 packages=setuptools.find_packages('src'),
                 package_dir={'': 'src'},
                 provides=['redsmaster'],
                 package_data={
                            'redsmaster': ['templates/*.tmpl']
                            },
                 platforms=['POSIX', 'UNIX', 'Linux'],
                 license='Apache',
                 install_requires=["cement",
                                   "python-hglib",
                                   "paramiko",
                                   "sqlalchemy",
                                   "passlib"],
                 entry_points={ 'console_scripts':
                                    ['redsmaster = redsmaster.app:main']},

      )

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
                 description='Revision controlled and encrypted document storage for cloud services.',
                 author='Tobias Pöppke',
                 author_email='tobias.poeppke@gmail.com',
                 url='https://bitbucket.org/tpoeppke/reds',
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
                                   "passlib",
								   "ecdsa"],
                 entry_points={ 'console_scripts':
                                    ['redsmaster = redsmaster.app:main']},

      )

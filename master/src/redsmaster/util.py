# coding=utf-8
"""
This module provides several utility functions.

This file is part of redsmaster, which was developed as part of a 
bachelor thesis at the Karlsruhe Institute of Technology, Germany and 
is hereby released under the following license terms.

Copyright 2013 Tobias Pöppke

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. 
"""

import os
import sys
import re
from getpass import getpass

from cement.core import exc as cementexc

from redsmaster import exc, log

LOG = log.get_logger("util")

def safe_path(path):
    userpath = os.path.normpath(os.path.expanduser(path))
    if not (userpath or re.search(r'[^A-Za-z0-9_\-\\\/]', userpath)):
        userpath = ""
    elif userpath == ".":
        userpath = ""
    return userpath


def show_config(app):
    if not app.config:
        return
    
    for section in app.config.get_sections():
        LOG.debug("section: %s: %s", section, 
                  app.config.get_section_dict(section))
            
            
def create_dirs(directory):
    if not os.path.isdir(directory):
        try:
            os.makedirs(directory)
        except OSError:
            pass
            
            
def get_pass(prompt):
    if sys.stdin.isatty():
        try:
            password = getpass(prompt)
        except cementexc.CaughtSignal:
            raise exc.AbortError("User aborted.")
    else:
        password = sys.stdin.readline().rstrip()
    return password
            
            
def get_confirmed_pass(prompt, retry):
    pw1 = get_pass(prompt)
    retries = 0
    
    # If this does not run in a terminal, we should not read the password twice
    if not sys.stdin.isatty():
        return pw1
    
    while (pw1 != get_pass("Please confirm the password: ") and 
           retries <= retry):
        LOG.warn("The passwords didn't match. Please try again!")
        pw1 = get_pass(prompt)
        retries += 1
        
    if retries > retry:
        raise exc.AbortError("Too many retries.")
    else:
        return pw1
        
        
def get_url_examples():
    return ("Amazon S3: s3://<bucketname>/<prefix>\n"
            "S3 compatible: s3c://<hostname>:<port>/<bucketname>/<prefix>\n"
            "Google Storage: gs://<bucketname>/<prefix>\n"
            "OpenStack/Swift: swift://<hostname>[:<port>]/"
            "<container>[/<prefix>]\n"
            "Local: local://<relative-path>\n\n"
            "See S3QL documentation for more information.")
        
        
def umount_hook(app_obj):
    if app_obj.encryptedfs.mounted:
        LOG.info("Unmounting the filesystem...")
        app_obj.encryptedfs.umount()
            
            
def has_forbidden_permissions(path, forbidden_permissions):
    mode = os.stat(path).st_mode
    if mode & forbidden_permissions:
        # Path has at least one of forbidden_permissions set.
        return True
    else:
        return False
    

def sane_port(port):
    int_port = int(port)
    if 1 >= int_port <= 65535 :
        return int_port
    else:
        return 2222
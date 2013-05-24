# coding=utf-8
"""This module provides the logging facilities to log access to the server.

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

from paramiko.util import logging
from cement.core import backend

SERVERLOG = logging.getLogger("SERVERLOG")
SERVERLOG.setLevel(logging.DEBUG)

formatter = logging.Formatter(
    "[%(asctime)s] %(threadName)s - %(levelname)s :: %(message)s")

def get_logger(name):
    """Returns the logger from Cement with proper console format."""
    console_formatter = logging.Formatter("%(message)s")
    logger = backend.minimal_logger(name)
    # The first handler is the console handler and we want clean output 
    # to the console.
    logger.handlers[0].setFormatter(console_formatter)
    return logger
# coding=utf-8
"""
This module provides a class for executing system commands.

It wraps the subprocess module for convenience.

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


import subprocess

from redsmaster import log

LOG = log.get_logger("command")

class Command(object):
    def __init__(self, cmd):
        super(Command, self).__init__()
        self.cmd = cmd
        
    def get_pipe(self, *args, **kw):
        LOG.debug("Command path: %s", self.cmd)

        command_list = []
        command_list.append(self.cmd)
        command_list.extend(args)
        LOG.debug("Executing: %s", command_list)
        
        proc = subprocess.Popen(command_list, stdout=subprocess.PIPE, 
                                stdin=subprocess.PIPE, 
                                stderr=subprocess.PIPE, **kw)
        LOG.debug("Process creation successful.")
        return proc
        
    def run(self, *args, **kw):
        proc = self.get_pipe(*args, **kw)
        out, err = proc.communicate()
        return out, err
        
    
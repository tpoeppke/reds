# coding=utf-8
"""
This module provides the interface and the base class for the versioncontrol 
component.

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

from cement.core import interface, handler


def versioncontrol_validator(class_, obj):
    members = [
        "_setup",
        "setup_repository",
        "new_repository",
        "get_repos_path",
        "is_versioncontrol_command",
        "get_needed_permission",
        "get_sane_command"
        ]
    
    interface.validate(IVersionControl, obj, members)


class IVersionControl(interface.Interface):
    class IMeta:
        label = "versioncontrol"
        validator = versioncontrol_validator
        
    Meta = interface.Attribute('VersionControl meta-data')
    
    def _setup(self, app_obj):
        """
        Make sure the handler is ready to receive further 
        requests.
        
        """
        
    def setup_repository(self, path):
        """
        Set up the repository for use with vcs.
        
        The path is seen as relative to the mountpoint.
        """
        
    def new_repository(self, path):
        """
        Return a new repository object with the given path.
        
        The path is seen as relative to the mountpoint.
        """
        
    def get_repos_path(self):
        """
        Return the path where the repositories are located on the disk.
        
        The path to the repositories is normally the repos directory, specified
        by the repodir config option, inside the mountpoint of the cloud 
        filesystem. 
        """
        
    @staticmethod
    def is_versioncontrol_command(command):
        """
        Returns True if the given command can be handled by this 
        type of version control system.
        """
        
    def get_needed_permission(self, command):
        """
        Returns the least permission needed to execute the given command. 
        """
        
    def get_sane_command(self, username, command, repopath):
        """
        Returns a sane command to be executed and a flag whether the command 
        is to be handled as a call to an external process or as a function 
        call. 
        
        If the user with username is not allowed to execute the command, None is
        returned and the caller has to make sure, that such a command is not 
        being executed. 
        """
        
        
class VersionControlHandler(handler.CementBaseHandler):
    class Meta:
        label = None
        interface = IVersionControl
        config_section = "vcs"
        
    def __init__(self):
        super(VersionControlHandler, self).__init__()
        
        
    def get_repos_path(self):
        mountpoint = self.app.configmanager.get_option('mountpoint')
        repodir = self.app.configmanager.get_option('repodir')
        repos_path = os.path.join(mountpoint, repodir)
        return repos_path

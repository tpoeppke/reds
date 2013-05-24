# coding=utf-8
"""This module contains the redsmaster exception classes.

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


class RedsError(Exception):
    """General exception class."""


class AbortError(RedsError):
    """Raised if the operation has to be aborted."""


class EFSError(RedsError):
    """Raised if an operation on the encrypted filesystem could not be 
    performed."""


class VersionControlError(RedsError):
    """Raised if there was an error in the versioncontrol system."""


class MountStatusError(RedsError):
    """Raised if an error in the mount status file was encountered."""


class DatabaseError(RedsError):
    """Raised if there was an error regarding the access control database."""

    
class ServerError(RedsError):
    """Raised if there was an error with the server."""
    
    
class NoPermissionError(RedsError):
    """Raised if the needed permission is not granted to the requesting user."""
    
    
class AuthenticationError(ServerError):
    """Raised if the authentication failed."""
    
    
class ForbiddenActionError(ServerError):
    """Raised if the user has not the necessary rights to execute the action."""
    def __init__(self, message, cmd):
        super(ForbiddenActionError, self).__init__(message)
        self.cmd = cmd
    
        
class TimeoutError(ServerError):
    """Raised if an operation timed out."""
# coding=utf-8
"""This module provides the interface definition and the base class
for the encrypted filesystem component.

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



from cement.core import interface, handler

def encryptedfs_validator(class_, obj):
    members = [
        "_setup",
        "mount",
        "mkfs",
        "umount",
        "is_mounted_at",
        ]
    
    interface.validate(IEncryptedFS, obj, members)


class IEncryptedFS(interface.Interface):
    class IMeta:
        label = "encryptedfs"
        validator = encryptedfs_validator
        
    Meta = interface.Attribute('EncryptedFS meta-data')
    
    def is_mounted_at(self, mountpoint):
        """
        Returns True if a filesystem is currently mounted at the 
        mountpoint.
        
        """
    
    def _setup(self, app_obj):
        """
        Is called to make sure the handler is ready to receive further 
        requests.
        
        """
        
    def mount(self, mountpoint):
        """
        Mount the remote storage to the given mountpoint.
        
        """
        
    def mkfs(self):
        """
        Create a filesystem on the remote storage.
                
        """
        
    def umount(self, mountpoint):
        """
        Unmount the filesystem at the mountpoint.
        
        """


class EncryptedFSHandler(handler.CementBaseHandler):
    class Meta:
        label = None
        interface = IEncryptedFS
        
    def __init__(self, *args, **kw):
        super(EncryptedFSHandler, self).__init__(*args, **kw)


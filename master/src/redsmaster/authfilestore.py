# coding=utf-8
"""This module contains the interface definitions and the base class for the
authfilestore component.

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

def authfilestore_validator(class_, obj):
    members = [
        "_setup",
        "get_credentials"
        ]
    
    interface.validate(IAuthfileStore, obj, members)

class IAuthfileStore(interface.Interface):
    class IMeta:
        label = "authfilestore"
        validator = authfilestore_validator
        
    Meta = interface.Attribute('Authfilestore meta-data')
    
    def _setup(self, app_obj):
        """
        Is called to make sure the handler is ready to receive further 
        requests.
        
        """
        
    def get_credentials(self, storage_url):
        """
        Get the credentials needed for authentication at the storage_url.
        
        Returns a StorageCredentials object.
        
        """
  

class AuthfileStoreBaseHandler(handler.CementBaseHandler):
    class Meta:
        label = None
        interface = IAuthfileStore
        
    def __init__(self, *args, **kw):
        super(AuthfileStoreBaseHandler, self).__init__(*args, **kw)
        
    def _setup(self, app_obj):
        super(AuthfileStoreBaseHandler, self)._setup(app_obj)
        
    def get_credentials(self):
        raise NotImplementedError()
        

class StorageCredentials(object):
    def __init__(self, storage_url, storage_login, storage_pw, encryption_pw):
        self.storage_url = storage_url
        self.storage_login = storage_login
        self.storage_pw = storage_pw
        self.encryption_pw = encryption_pw
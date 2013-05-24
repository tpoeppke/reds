# coding=utf-8
"""
This extension provides a plaintext AuthfileStore.

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

import ConfigParser

from cement.core import handler

from redsmaster import authfilestore, exc, util, log

LOG = log.get_logger("authfilestore")


class AuthfileStoreHandler(authfilestore.AuthfileStoreBaseHandler):
    """Handler for plaintext authfiles using ConfigParser syntax."""
    class Meta:
        label = "authfilestore"
        interface = authfilestore.IAuthfileStore
        
    def __init__(self, *args, **kw):
        super(AuthfileStoreHandler, self).__init__(*args, **kw)
        self.authfile = None
        self.parsed = False
        self.storage_url = None
        self.auth_config = None
        
    def _setup(self, app_obj):
        super(AuthfileStoreHandler, self)._setup(app_obj) 
        
    def _prompt_credential(self, cred_name, confirm=False, retry=3):
        cred_name = cred_name.replace("-", " ")
        prompt = "Please enter the %s for %s: " % (cred_name, self.storage_url)
        if confirm:
            return util.get_confirmed_pass(prompt, retry)
        else:
            return util.get_pass(prompt)
        
    def _prompt_credentials(self, encpw_only):
        store_login = ""
        store_pw = ""
        try:
            if not encpw_only:
                store_login = self._prompt_credential('login-name')
                store_pw = self._prompt_credential('login-password')
        
            encryption_pw = self._prompt_credential('filesystem-password', 
                                                    confirm=True)
        except EOFError:
            raise exc.AbortError("User aborted.")
        
        return store_login, store_pw, encryption_pw
    
    def _get_matching_section(self):
        matchsect = None
        for section in self.auth_config.sections():
            # Find the last section which matches the storage-url. 
            try:
                url = self.auth_config.get(section, 'storage-url')
            except KeyError:
                continue
            if self.storage_url.startswith(url):
                matchsect = section
        return matchsect
        

    def _parse_authfile(self):
        LOG.debug("Parsing authfile %s...", self.authfile)
        self.auth_config = ConfigParser.ConfigParser()
        try:
            parsed = self.auth_config.read(self.authfile)
            self.parsed = self.parsed or parsed
        except ConfigParser.Error as err:
            LOG.warn("Could not parse authfile. Reason: %s", err)

    def get_credentials(self, confirm, encpw_only=False):
        self.authfile = self.app.configmanager.get_option('authfile')
        self.storage_url = self.app.configmanager.get_option('storage-url')
        
        if self.authfile and not self.parsed:
            self._parse_authfile()
            
        store_login = None
        store_pw = None
        encryption_pw = None
        
        if not self.parsed:
            store_login, store_pw, encryption_pw = self._prompt_credentials(
                                                                    encpw_only)
        else:
            matchsect = self._get_matching_section()
            if matchsect:
                def get_option(opt_name, confirm=False):
                    try:
                        return self.auth_config.get(matchsect, opt_name)
                    except ConfigParser.NoOptionError:
                        return self._prompt_credential(opt_name,
                                                       confirm=confirm)
                
                store_login = get_option('login-name')
                store_pw = get_option('login-password')
                encryption_pw = get_option('filesystem-password', 
                                           confirm=confirm)
        
        credentials = authfilestore.StorageCredentials(
                                                storage_url=self.storage_url,
                                                storage_login=store_login, 
                                                storage_pw=store_pw, 
                                                encryption_pw=encryption_pw)
        return credentials
    

def load():
    handler.register(AuthfileStoreHandler)
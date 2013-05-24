# coding=utf-8
"""This module the StatusManager class.

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
import stat
import shelve
from contextlib import closing as ctx

from redsmaster import config, exc, log


STATUS_FILE = os.path.join(config.CACHE_DIR, ".~status-lock.db")
STATUS_MODE = stat.S_IRUSR | stat.S_IWUSR


LOG = log.get_logger("statusmanager")


class RedsMasterStatus(object):
    def __init__(self, storage_url, mountpoint, serverlog, pid=0):
        super(RedsMasterStatus, self).__init__()
        self.mountpoint = mountpoint
        self.storage_url = storage_url
        self.serverlog = serverlog
        self.pid = pid

        
class StatusManager(object):
    def __init__(self):
        super(StatusManager, self).__init__()
        self.app = None
        self._mountpoint = None
        self._storage_url = None
        self._pid = None
        
    @property
    def mountpoint(self):
        return self.app.configmanager.get_option('mountpoint').encode("utf-8")
        
    @property
    def storage_url(self):
        return self.app.configmanager.get_option("storage-url").encode("utf-8")
        
    @property
    def serverlog(self):
        return self.app.configmanager.get_option('serverlog').encode("utf-8")
    
    def setup(self, app_obj):
        self.app = app_obj
        
        
    def _update_status(self):
        with ctx(shelve.open(STATUS_FILE)) as dbase:
            for mountpoint, status in dbase.iteritems():
                fs_mounted = self.app.encryptedfs.is_mounted_at(
                                                            status.mountpoint)
                if not fs_mounted:
                    LOG.info("Wrong status entry for mountpoint '%s'. "
                             "Cleaning up. Perhaps manually unmounted?", 
                             mountpoint)
                    self.unregister_server()
            
    def register_server(self, status):
        with ctx(shelve.open(STATUS_FILE)) as dbase:
            dbase[self.mountpoint] = status
    
    def unregister_server(self):
        with ctx(shelve.open(STATUS_FILE)) as dbase:
            try:
                del dbase[self.mountpoint]
            except KeyError:
                dbase.clear()
    
    @staticmethod
    def _get_first_status():
        with ctx(shelve.open(STATUS_FILE)) as dbase:
            for status in dbase.itervalues():
                return status
    
    @staticmethod
    def _get_status_count():
        with ctx(shelve.open(STATUS_FILE)) as dbase:
            count = len(dbase)
            LOG.debug("Nr of status entries: %i", count)
            return count
        
    def _update_config_from_status(self, status):
        self.app.configmanager.set_option('mountpoint', status.mountpoint, quiet=False)
        self.app.configmanager.set_option('storage-url', status.storage_url, 
                                  quiet=False)
        self.app.configmanager.set_option('serverlog', status.serverlog, quiet=False)
            
    def start_server(self):
        LOG.debug("Updating status...")
        self._update_status()
        status_count = self._get_status_count()
        
        # Allow only one master to run right now.
        if status_count == 0:
            LOG.debug("Trying to mount")
            self.app.encryptedfs.mount()
            # The server has to call register_status himself, 
            # because only the server knows its pid.
            LOG.debug("Trying to setup the accessmanager")
            self.app.accessmanager.setup(self.app)
            LOG.debug("Starting the server")
            self.app.servermanager.start()
        elif status_count == 1:
            raise exc.AbortError("There is currently running another master.")
        elif status_count > 0:
            # Status file should not contain more than one entry.
            raise exc.MountStatusError("Something is wrong with the "
                                       "status file.")
        
    def unmount(self):
        self.app.accessmanager.close()
        self.app.encryptedfs.umount()
        
    def stop_server(self):
        self._update_status()
        status_count = self._get_status_count()
        
        if status_count == 1:
            curr_status = self._get_first_status()
            self._update_config_from_status(curr_status)
            try:
                self.app.servermanager.stop(curr_status.pid)
                #os.remove(STATUS_FILE)
            except exc.EFSError:
                LOG.error("There was an error while unmounting.")
        elif status_count == 0:
            raise exc.AbortError("There is no master running at this moment.")
        else:
            raise exc.MountStatusError("Something is wrong with the "
                                       "status file.")
            
    def restart_server(self):
        try:
            self.stop_server()
        except exc.AbortError:
            LOG.info("There was no master running... Starting new one.")
        self.start_server()
    
    def get_current_status(self):
        self._update_status()
        status_count = self._get_status_count()
        
        if status_count == 1:
            curr_status = self._get_first_status()
            self._update_config_from_status(curr_status)
            return curr_status
        elif status_count == 0:
            raise exc.AbortError("There is no master running at this moment.")
        else:
            raise exc.MountStatusError("Something is wrong with the "
                                       "status file.")
        


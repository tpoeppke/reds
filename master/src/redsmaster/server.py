# coding=utf-8
"""
This module provides the interface and the base class for the servermanager 
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

import signal
import os
import time
import atexit
import logging
from logging.handlers import RotatingFileHandler

from cement.core import interface, handler, backend

from redsmaster import config, exc, status, log
from redsmaster.daemonize import daemonize


LOG = log.get_logger("serverbase")
SERVERLOG = log.SERVERLOG


def server_validator(class_, obj):
    members = [
        "_setup",
        "start",
        "stop",
        "_run",
        "exit",
        ]
    
    interface.validate(IServerManager, obj, members)
        
class IServerManager(interface.Interface):
    class IMeta:
        label = "servermanager"
        validator = server_validator
        
    def _setup(self):
        """ Make sure the server is ready to use."""
        pass
    
    def start(self):
        """ Start the server to receive requests from clients."""
        pass
    
    @staticmethod
    def stop(pid):
        """ Stop the server with the proccess id pid."""
        pass
    
    def _run(self):
        """ Runs the main server loop, takes requests and processes them.
        
        This method must be implemented by subclasses of BaseServerManager.
        """
        pass
    
    def exit(self):
        """ Perform all necessary steps to exit the server.
        
        This method must be implemented by subclasses of BaseServerManager.
        """
        pass


class BaseServerManager(handler.CementBaseHandler):
    class Meta:
        label = None
        interface = IServerManager
        
    def __init__(self, **kw):
        super(BaseServerManager, self).__init__(**kw)
        self.server_logfile = None
        self.status = None
        
    def _setup(self, app_obj):
        super(BaseServerManager, self)._setup(app_obj)
        
    def _setup_serverlog(self):
        self.server_logfile = self.app.configmanager.get_option('serverlog')
        filehandler = RotatingFileHandler(self.server_logfile, 
                                          backupCount=5)
        filehandler.setLevel(logging.DEBUG)
        filehandler.setFormatter(log.formatter)
        SERVERLOG.addHandler(filehandler)
        
        mountpoint = self.app.configmanager.get_option('mountpoint', self.app)
        storage_url = self.app.configmanager.get_option('storage-url', self.app)
        
        SERVERLOG.info("Starting log for storage '%s' at mountpoint '%s'.",
                       storage_url, mountpoint)
        
    def _update_current_status(self):
        mountpoint = self.app.configmanager.get_option('mountpoint')
        storage_url = self.app.configmanager.get_option('storage-url')
        serverlog = self.app.configmanager.get_option('serverlog')
        
        self.status = status.RedsMasterStatus(mountpoint=mountpoint,
                                              storage_url=storage_url,
                                              serverlog=serverlog,
                                              pid=os.getpid())
    
    def _pre_daemonize(self):
        """
        Here the subclass can implement what has to be done before "
        the daemon is run.
        """
        pass
    
    def _run(self):
        """
        Template method for the subclass to overwrite. Here the subclass 
        can implement what has to be done to run the server.
        """
    
    def start(self):
        LOG.debug("Setup serverlog")
        self._setup_serverlog()
        LOG.debug("Execute pre-daemonize")
        self._pre_daemonize()
        if not self.app.pargs.fg:
            LOG.debug("Make the daemon")
            daemonize()
        SERVERLOG.debug("Updating status")
        self._update_current_status()
        
        atexit.register(self.exit)
        
        SERVERLOG.debug("Register server back to statusmanager")
        self.app.statusmanager.register_server(self.status)
        SERVERLOG.debug("Actually run the server")
        self._run()
    
    @staticmethod
    def stop(pid):
        try:
            LOG.info("Killing process with pid: %s" % pid)
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(1)
        except OSError as err:
            err = str(err)
            if not err.find("No such process") > 0:
                raise exc.ServerError("Could not stop the server!\n%s" % err)
            
    def exit(self):
        # We have to unregister here 
        SERVERLOG.info("Unmounting storage...")
        self.app.statusmanager.unmount()
        self.app.statusmanager.unregister_server()
        SERVERLOG.info("Exiting daemon!")
           
            
config.register_option(name="fg", section="general", action="store_true",
                       help=("Don't daemonize the server and stay in "
                             "foreground."))
        

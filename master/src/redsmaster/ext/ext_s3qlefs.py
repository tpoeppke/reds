# coding=utf-8
"""This extension provides the S3QL filesystem to redsmaster.

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
import tempfile

from cement.core import handler

from redsmaster import config, efs, command, exc, util, log

LOG = log.get_logger("s3qlefs")

class S3QLHandler(efs.EncryptedFSHandler):
    """This class provides an interface for the S3QL encrypted filesystem."""    
    class Meta:
        label = "s3qlhandler"
        interface = efs.IEncryptedFS
        
    def __init__(self, *args, **kw):
        super(S3QLHandler, self).__init__(*args, **kw)
        self._path = None
        self._mountpoint = None
        self._store = None
        self._mounted = False
        self._temp_authfile = None
        self._credentials = None
        self._mountcmd = None
        self._umountcmd = None
        self._mkfscmd = None
        self._fsckcmd = None
        
    def __del__(self):
        if self._temp_authfile:
            self._temp_authfile.close()
            
    @property
    def mountcmd(self):
        if not self._mountcmd:
            cmd = os.path.join(self.path, "mount.s3ql")
            self._mountcmd = command.Command(cmd)
        return self._mountcmd
    
    @property
    def mkfscmd(self):
        if not self._mkfscmd:
            cmd = os.path.join(self.path, "mkfs.s3ql")
            self._mkfscmd = command.Command(cmd)
        return self._mkfscmd
            
    @property
    def umountcmd(self):
        if not self._umountcmd:
            cmd = os.path.join(self.path, "umount.s3ql")
            self._umountcmd = command.Command(cmd)
        return self._umountcmd
    
    @property
    def fsckcmd(self):
        if not self._fsckcmd:
            cmd = os.path.join(self.path, "fsck.s3ql")
            self._fsckcmd = command.Command(cmd)
        return self._fsckcmd
            
    @property
    def mountpoint(self):
        if not self._mountpoint:
            self._mountpoint = self.app.configmanager.get_option('mountpoint')
        return self._mountpoint
    
    @property
    def path(self):
        if not self._path:
            self._path = self.app.configmanager.get_option('s3ql-path')
        return self._path
    
    @property
    def store(self):
        if not self._store:
            self._store = self.app.configmanager.get_option('storage-url')
        return self._store
    
    @staticmethod
    def is_mounted_at(mountpoint):
        sane_mount = config.options['mountpoint'].sanitize(mountpoint)
        mounted = False
        if sane_mount:
            # S3QL automatically creates a lost+found directory, 
            # so we check for it, to determine if it is already mounted.
            lfdir = os.path.join(sane_mount, "lost+found")
            mounted = os.path.isdir(lfdir)
        return mounted
          
    @property  
    def mounted(self):
        if not self._mounted:
            self._mounted = self.is_mounted_at(self.mountpoint)
        return self._mounted

    def _setup(self, app_obj):
        super(S3QLHandler, self)._setup(app_obj)
        
    def _get_pipe_with_authfile(self, cmd, *args):
        LOG.debug("authfile = %s" % self._temp_authfile.name)
            
        args_list = []
        args_list.extend(args)
        args_list.extend(["--authfile", self._temp_authfile.name])
        
        return cmd.get_pipe(*args_list)
        
    def mount(self):
        """
        Mounts the storage-url to the mountpoint, 
        which are both retrieved from the config.
        """
        if not os.path.isdir(self.mountpoint):
            raise exc.AbortError("The mountpoint '%s' is not a directory." % 
                                 self.mountpoint)
            
        self._update_temp_authfile()
        proc = self._get_pipe_with_authfile(self.mountcmd, self.store, 
                                            self.mountpoint)
        err = proc.communicate()[1]
            
        if proc.returncode != 0:
            raise exc.EFSError("There was an error while mounting:\n'%s'" % err)
        else:
            self._mounted = True
    
    def umount(self):
        """Unmount the current mountpoint."""
        # The umount will fail if someone is still accessing the mount. 
        # But because of the lazy option, s3ql will unmount it 
        # as soon as possible.
        proc = self.umountcmd.get_pipe(self.mountpoint, "--lazy")
        err = proc.communicate()[1]
        
        if proc.returncode != 0:
            raise exc.EFSError("There was an error while unmounting:\n'%s'" % 
                               err)
        
    
    def _update_temp_authfile(self, confirm=False, encpw_only=False):
        if self._temp_authfile:
            return
        
        if self.store.startswith("local:"):
            encpw_only = True

        self._credentials = creds = self.app.authfilestore.\
                                    get_credentials(confirm, encpw_only)
        authfile = ("[reds]\n"
                    "storage-url: %(storage-url)s\n"
                    "backend-login: %(storage-login)s\n"
                    "backend-password: %(storage-pw)s\n"
                    "fs-passphrase: %(encryption-pw)s\n") % \
                                    {'storage-url': creds.storage_url[0:8],
                                     'storage-login': creds.storage_login,
                                     'storage-pw': creds.storage_pw,
                                     'encryption-pw': creds.encryption_pw}
                                    
        self._temp_authfile = tempfile.NamedTemporaryFile(prefix="reds")
        self._temp_authfile.write(authfile)
        self._temp_authfile.flush()
    
    def mkfs(self):
        """Create a new filesystem on the storage-url."""
        self._update_temp_authfile(confirm=True)
        
        args_list = [self.mkfscmd, self.store]
        
        if self.app.pargs.force:
            LOG.debug("Forcing request...")
            args_list.append("--force")
        
        proc = self._get_pipe_with_authfile(*args_list)
        
        # S3QL asks for the password only once if no tty is present.
        password = "%(pw)s\n" % {'pw': self._credentials.encryption_pw}
        err = proc.communicate(password)[1]
        
        if proc.returncode != 0:
            raise exc.EFSError("Could not initialise the filesystem: %s" % err)
        
        LOG.debug("Filesystem created successfully")
        
    def fsck(self):
        """Check the remote filesystem at the storage-url."""
        self._update_temp_authfile()
        
        LOG.info("Checking remote filesystem...")
        args_list = [self.fsckcmd, self.store]
        
        if self.app.pargs.force:
            LOG.debug("Forcing request...")
            args_list.append("--force")
        
        proc = self._get_pipe_with_authfile(*args_list)
        proc.communicate()
        
        if proc.returncode != 0:
            raise exc.EFSError("There was an error checking the filesystem.")
        
        LOG.info("Filesystem check successful.")


config.register_option(name="s3ql-path", section="paths", default="", 
                       action="store", metavar="<path>", 
                       sanitizer=util.safe_path, 
                       help="""Path to the s3ql binaries.""")

config.register_option(name="force", section="general", action="store_true", 
                       help=("Force the operation to run."))

def load():
    handler.register(S3QLHandler)
# coding=utf-8
"""
This module contains the command line interface.

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
import time
import shutil
import pkg_resources

from cement.core import foundation, controller, handler, hook
from redsmaster.ext import (ext_s3qlefs, ext_authfilestore, ext_hgvcs, 
                            ext_sshserver)

from redsmaster import (config, efs, versioncontrol, server, util, exc, 
                        status, accesscontrol, log, authfilestore)

LOG = log.get_logger("masterapp")

DEFAULT_ARGS = config.get_default_args()
STORAGEURL_ARG = config.options['storage-url'].get_arg()
MOUNTPOINT_ARG = config.options['mountpoint'].get_arg()
FORCE_ARG = config.options['force'].get_arg()
FOREGROUND_ARG = config.options['fg'].get_arg()


class MasterBaseController(controller.CementBaseController):
    class Meta:
        label = "base"
        description = ("This is redsmaster, the server component of reds.\n"
                "Reds stands for revision controlled document storage.\n\n"
                "To start using redsmaster type once to setup the storage:\n"
                "    redsmaster setup <storage-address>\n\n"
                "To start serving type:\n"
                "    redsmaster start <storage-address>\n\n"
                "Available as storage-address are:\n%s") % \
                util.get_url_examples()
        usage = ("redsmaster <cmd> [-h, --help] [--debug] [--quiet] "
                 "[--configfile <path>] [--authfile <path>]")
        config_section = "general"
        arguments = DEFAULT_ARGS
        
    @controller.expose(hide=True, help="Default is to print the help message.")
    def default(self):
        self.app.configmanager.setup_config()
        self.app.args.print_help()
        
        
class FSCKController(controller.CementBaseController):
    class Meta:
        label = "fsck"
        description = "Check the remote filesystem."
        config_section = "general"
        arguments = DEFAULT_ARGS + [STORAGEURL_ARG, FORCE_ARG]
        
    @controller.expose(hide=True)
    def default(self):
        self.app.configmanager.setup_config()
        LOG.info("Checking the remote filesystem...")
        try:
            self.app.encryptedfs.fsck()
        except exc.RedsError as err:
            LOG.error("%s" % err)        
        
        
class AddUserController(controller.CementBaseController):
    class Meta:
        label = "adduser"
        description = ("Add a user to the database. If the user already exists "
                       "add the user to the given roles and/or change the key "
                       "or password.")
        config_section = "general"
        arguments = DEFAULT_ARGS + [
                                (["user"], dict(help="The username to add")),
                                (["roles"], dict(help="The role(s) to which"
                                                 " the user should belong",
                                                 nargs="*")),
                                (["--publickey"], dict(help="The public key"
                                                       " file of the new "
                                                       "user.",
                                                       metavar="<path>")),
                                (["--password"], dict(help="Ask the password "
                                                      "for the new user. "
                                                      "Try to only use "
                                                      "public keys "
                                                      "whenever possible.", 
                                                      action="store_true"))
                                ]
        usage = ("redsmaster adduser <user> <role(s)> [--publickey <path>] " 
                "[--password <pass>]")
        
    @controller.expose(hide=True)
    def default(self):
        self.app.configmanager.setup_config()
        
        try:
            status = self.app.statusmanager.get_current_status()
        except exc.AbortError as err:
            LOG.info("%s\nAborting!", err)
            return
        
        self.app.accessmanager.setup(self.app)
        
        username = self.app.pargs.user
        try:
            self.app.accessmanager.add_user(username)
            for role in self.app.pargs.roles:
                try:
                    self.app.accessmanager.assign_user(username, role)
                except exc.DatabaseError as err:
                    LOG.info("Could not assign user to role %s. %s\nSkipping.", 
                             role, err)
        except exc.DatabaseError as err:
            LOG.info("Could not add the user: %s", err)
        except exc.AbortError as err:
            LOG.info("Could not add the user: %s\nAborting!", err)
            return
            
        if self.app.pargs.publickey:
            try:
                with open(self.app.pargs.publickey) as pubkey:
                    # Public keys consist only of one line
                    key = pubkey.readline()
                    self.app.accessmanager.assign_auth_credential(username, 
                                                            key, "publickey")
            except (exc.DatabaseError, IOError) as err:
                LOG.info("Could not add the public key: %s", err)
        
        if self.app.pargs.password:
            try:
                password = util.get_confirmed_pass("Please enter the new "
                                                   "password for user '%s': " % 
                                                   username, 1)
                self.app.accessmanager.assign_auth_credential(username, 
                                                              password, 
                                                              "password")
            except exc.DatabaseError as err:
                LOG.info("Could not add the password: %s", err)
                    
                    
class DelUserController(controller.CementBaseController):
    class Meta:
        label = "deluser"
        description = ("Delete the given user from the database.")
        config_section = "general"
        arguments = DEFAULT_ARGS + [
                                (["user"], dict(help="The username to delete"))
                                ]
        usage = ("redsmaster deluser <user>")
        
    @controller.expose(hide=True)
    def default(self):
        self.app.configmanager.setup_config()
        
        try:
            status = self.app.statusmanager.get_current_status()
        except exc.AbortError as err:
            LOG.info("%s\nAborting!", err)
            return
        
        self.app.accessmanager.setup(self.app)
        
        username = self.app.pargs.user
        try:
            self.app.accessmanager.del_user(username)
        except exc.DatabaseError as err:
            LOG.info("Could not delete the user: %s", err)
        except exc.AbortError as err:
            LOG.info("Could not delete the user: %s\nAborting!", err)
            return
        
        
class AddRoleController(controller.CementBaseController):
    class Meta:
        label = "addrole"
        description = ("Add a role to the database. If the role already exists "
                       "add the given users to the role.")
        config_section = "general"
        arguments = DEFAULT_ARGS + [
                                (["role"], dict(help="The role to add.")),
                                (["users"], dict(help="The user(s) to add "
                                                 "to the role",
                                                 nargs="*"))
                                ]
        usage = ("redsmaster addrole <role> <users>")
        
    @controller.expose(hide=True)
    def default(self):
        self.app.configmanager.setup_config()
        
        try:
            status = self.app.statusmanager.get_current_status()
        except exc.AbortError as err:
            LOG.info("%s\nAborting!", err)
            return
        
        self.app.accessmanager.setup(self.app)
        
        rolename = self.app.pargs.role
        try:
            self.app.accessmanager.add_role(rolename)
            for username in self.app.pargs.users:
                try:
                    self.app.accessmanager.assign_user(username, rolename)
                except exc.DatabaseError as err:
                    LOG.info("Could not assign user to role %s. %s\nSkipping.", 
                             rolename, err)
        except exc.DatabaseError as err:
            LOG.info("Could not add the role: %s", err)
        except exc.AbortError as err:
            LOG.info("Could not add the role: %s\nAborting!", err)
            return  
        
        
class DelRoleController(controller.CementBaseController):
    class Meta:
        label = "delrole"
        description = ("Delete the given role from the database.")
        config_section = "general"
        arguments = DEFAULT_ARGS + [
                                (["role"], dict(help="The role to delete"))
                                ]
        usage = ("redsmaster delrole <role>")
        
    @controller.expose(hide=True)
    def default(self):
        self.app.configmanager.setup_config()
        
        try:
            status = self.app.statusmanager.get_current_status()
        except exc.AbortError as err:
            LOG.info("%s\nAborting!", err)
            return
        
        self.app.accessmanager.setup(self.app)
        
        role = self.app.pargs.role
        try:
            self.app.accessmanager.del_role(role)
        except exc.DatabaseError as err:
            LOG.info("Could not delete the user: %s", err)
        except exc.AbortError as err:
            LOG.info("Could not delete the user: %s\nAborting!", err)
            return
        
        
class AssignUserController(controller.CementBaseController):
    class Meta:
        label = "assignuser"
        description = ("Assign the given user to the given role(s).")
        config_section = "general"
        arguments = DEFAULT_ARGS + [
                                (["user"], dict(help="The user to assign")),
                                (["roles"], dict(help="The role(s) to assign "
                                                 "the user to",
                                                 nargs="+"))
                                ]
        usage = ("redsmaster assignuser <user> <roles>")
        
    @controller.expose(hide=True)
    def default(self):
        self.app.configmanager.setup_config()
        
        try:
            status = self.app.statusmanager.get_current_status()
        except exc.AbortError as err:
            LOG.info("%s\nAborting!", err)
            return
        
        self.app.accessmanager.setup(self.app)
        
        user = self.app.pargs.user
        roles = self.app.pargs.roles
        
        for role in roles:
            try:
                self.app.accessmanager.assign_user(user, role)
            except exc.DatabaseError as err:
                LOG.info("Could not assign the user: %s", err)
                continue
            except exc.AbortError as err:
                LOG.info("Could not assign the user: %s\nAborting!", err)
                break
            

class DeassignUserController(controller.CementBaseController):
    class Meta:
        label = "deassignuser"
        description = ("Deassign the given user from the given role(s).")
        config_section = "general"
        arguments = DEFAULT_ARGS + [
                                (["user"], dict(help="The user to deassign")),
                                (["roles"], dict(help="The role(s) to deassign "
                                                 "the user from",
                                                 nargs="+"))
                                ]
        usage = ("redsmaster deassignuser <user> <roles>")
        
    @controller.expose(hide=True)
    def default(self):
        self.app.configmanager.setup_config()
        
        try:
            status = self.app.statusmanager.get_current_status()
        except exc.AbortError as err:
            LOG.info("%s\nAborting!", err)
            return
        
        self.app.accessmanager.setup(self.app)
        
        user = self.app.pargs.user
        roles = self.app.pargs.roles
        
        for role in roles:
            try:
                self.app.accessmanager.deassign_user(user, role)
            except exc.DatabaseError as err:
                LOG.info("Could not deassign the user: %s", err)
                continue
            except exc.AbortError as err:
                LOG.info("Could not deassign the user: %s\nAborting!", err)
                break
            

class GrantPermissionController(controller.CementBaseController):
    class Meta:
        label = "grantpermission"
        description = ("Grant the given permission to the user.")
        config_section = "general"
        arguments = DEFAULT_ARGS + [
                                (["role"], dict(help="The role to grant the "
                                                "permission to")),
                                (["operation"], dict(help="The operation to "
                                                 "grant")),
                                (["repository"], dict(help="The repository to "
                                                      "grant the permission on. "
                                                      "Leave empty if its an "
                                                      "admin operation.",
                                                      nargs="?",
                                                      default=""))
                                ]
        usage = ("redsmaster grantpermission <role> <operation> <repository>")
        
    @controller.expose(hide=True)
    def default(self):
        self.app.configmanager.setup_config()
        
        try:
            status = self.app.statusmanager.get_current_status()
        except exc.AbortError as err:
            LOG.info("%s\nAborting!", err)
            return
        
        self.app.accessmanager.setup(self.app)
        
        role = self.app.pargs.role
        operation = self.app.pargs.operation
        repository = self.app.pargs.repository
        
        try:
            self.app.accessmanager.grant_permission(operation, repository, role)
        except exc.DatabaseError as err:
            LOG.info("Could not grant the permission: %s", err)
        except exc.AbortError as err:
            LOG.info("Could not grant the permission: %s\nAborting!", err)
            return
        
        
class RevokePermissionController(controller.CementBaseController):
    class Meta:
        label = "revokepermission"
        description = ("Revoke the given permission to the role.")
        config_section = "general"
        arguments = DEFAULT_ARGS + [
                                (["role"], dict(help="The role to revoke the "
                                                "permission from")),
                                (["operation"], dict(help="The operation to "
                                                 "revoke")),
                                (["repository"], dict(help="The repository to "
                                                      "revoke the permission. "
                                                      "Leave empty if its an "
                                                      "admin operation.",
                                                      nargs="?",
                                                      default=""))
                                ]
        usage = ("redsmaster revokepermission <user> <operation> <object>")
        
    @controller.expose(hide=True)
    def default(self):
        self.app.configmanager.setup_config()
        
        try:
            status = self.app.statusmanager.get_current_status()
        except exc.AbortError as err:
            LOG.info("%s\nAborting!", err)
            return
        
        self.app.accessmanager.setup(self.app)
        
        role = self.app.pargs.role
        operation = self.app.pargs.operation
        repository = self.app.pargs.repository
        
        try:
            self.app.accessmanager.revoke_permission(operation, repository, 
                                                     role)
        except exc.DatabaseError as err:
            LOG.info("Could not revoke the permission: %s", err)
        except exc.AbortError as err:
            LOG.info("Could not revoke the permission: %s\nAborting!", err)
            return
                    

class StartController(controller.CementBaseController):
    class Meta:
        label = "start"
        description = "Start serving"
        config_section = "general"
        arguments = DEFAULT_ARGS + [STORAGEURL_ARG, MOUNTPOINT_ARG, 
                                    FOREGROUND_ARG]
        
    @controller.expose(hide=True, help="Start serving")
    def default(self):
        self.app.configmanager.setup_config()
        LOG.info("Starting server...")
        try:
            self.app.statusmanager.start_server()
        except exc.RedsError as err:
            LOG.error("%s", err)
        except Exception:
            util.umount_hook(self.app)
            raise
            
 
class StopController(controller.CementBaseController):
    class Meta:
        label = "stop"
        description = "Stop serving"
        config_section = "general"
        arguments = DEFAULT_ARGS
        
    @controller.expose(hide=True, help="Stop serving")
    def default(self):
        self.app.configmanager.setup_config()
        try:
            self.app.statusmanager.stop_server()
        except exc.AbortError as err:
            LOG.error("%s" , err)
        except exc.EFSError as err:
            LOG.error("The filesystem could not be unmounted.")
            
            
class SetupController(controller.CementBaseController):
    class Meta:
        label = "setup"
        description = "Setup the program for use."
        config_section = "general"
        arguments = DEFAULT_ARGS + [STORAGEURL_ARG, MOUNTPOINT_ARG, FORCE_ARG]
    
    def _setup_directories(self):
        configmgr = self.app.configmanager
        mountpoint = configmgr.get_option('mountpoint')
        configfile = configmgr.get_option('configfile')
        configdir = os.path.dirname(configfile)
        
        util.create_dirs(mountpoint)
        util.create_dirs(configdir)
        config_tmpl = pkg_resources.resource_filename("redsmaster", 
                                            "templates/redsmaster.conf.tmpl")
            
        shutil.copyfile(config_tmpl, os.path.join(configdir, 
                                                  "redsmaster.conf.example"))
        util.create_dirs(config.CACHE_DIR)
    
    @controller.expose(hide=True, help="Setup the storage")
    def default(self):
        configmgr = self.app.configmanager
        configmgr.setup_config()
        LOG.info("Setting up the directories...")
        self._setup_directories()
        mountpoint = configmgr.get_option('mountpoint')
        repodir = os.path.join(mountpoint, 
                               configmgr.get_option('repodir'))
        
        LOG.info("Creating filesystem on the remote storage...")
        try:
            self.app.encryptedfs.mkfs()
            # We need time for the changes to propagate
            time.sleep(1)
            self.app.encryptedfs.mount()
            util.create_dirs(repodir)
            self.app.accessmanager.initial_setup(self.app)
        except exc.EFSError as err:
            LOG.error("%s", err)
        except exc.AbortError as err:
            LOG.info("Aborting the operation. Reason:\n%s", err)
        except exc.DatabaseError as err:
            LOG.error("There was an error with the access control "
                     "database:\n%s", err)
        else:
            LOG.info("The storage is now ready for use. "
                 "Use the start command to use it.")
        finally:
            self.app.accessmanager.close()
            util.umount_hook(self.app)
            
            
class MasterApp(foundation.CementApp):
    class Meta:
        label = "redsmaster"
        base_controller = MasterBaseController
        arguments_override_config = True
        config_section = "general"
        config_files = [config.options['configfile'].default,]

        authfilestore_handler = ext_authfilestore.AuthfileStoreHandler        
        encryptedfs_handler = ext_s3qlefs.S3QLHandler
        versioncontrol_handler = ext_hgvcs.HgHandler
        servermanager_handler = ext_sshserver.SSHServerManager
        
        extensions = [
                    'redsmaster.ext.ext_authfilestore',
                    'redsmaster.ext.ext_sshserver',
                    'redsmaster.ext.ext_s3qlefs',
                    ]
        
    def __init__(self, *args, **kw):
        super(MasterApp, self).__init__(*args, **kw)
        self.reds_handlers = [
                        "encryptedfs",
                        "versioncontrol",
                        "authfilestore",
                        "servermanager",
                        ]
        self.accessmanager = None
        self.statusmanager = None
        self.configmanager = None
               
    def setup(self):
        super(MasterApp, self).setup()
        self._setup_reds_handlers()
        self._setup_access_manager()
        self._setup_status_manager()
        self._setup_config_manager()
        
    def _setup_handler(self, name):
        LOG.debug("Setting up %s handler...", name)
        redshandler = self._meta.__dict__["%s_handler" % name]
        handler_obj = self._resolve_handler(name, redshandler)
        if handler_obj:
            setattr(self, name, handler_obj)
        else:
            raise KeyError("Handler not found.")
        
    def _setup_reds_handlers(self):
        for redshandler in self.reds_handlers:
            try:
                self._setup_handler(redshandler)
            except KeyError:
                LOG.debug("Handler %s not found. Skipping...", redshandler)
                continue
            
    def _setup_access_manager(self):
        self.accessmanager = accesscontrol.RedsAccessManager()
    
    def _setup_status_manager(self):
        self.statusmanager = status.StatusManager()
        self.statusmanager.setup(self)
    
    def _setup_config_manager(self):
        self.configmanager = config.ConfigManager(self)
            
            
def _define_handlers(app):
    handler.define(efs.IEncryptedFS)
    handler.define(versioncontrol.IVersionControl)
    handler.define(authfilestore.IAuthfileStore)
    handler.define(server.IServerManager)
    handler.register(SetupController)
    handler.register(StartController)
    handler.register(StopController)
    handler.register(FSCKController)
    handler.register(AddUserController)
    handler.register(DelUserController)
    handler.register(AddRoleController)
    handler.register(DelRoleController)
    handler.register(AssignUserController)
    handler.register(DeassignUserController)
    handler.register(GrantPermissionController)
    handler.register(RevokePermissionController)


def register_hooks():
    hook.register("pre_setup", _define_handlers)


def setup_and_run(app_obj):
    register_hooks()
    app_obj.setup()
    app_obj.run()


def main():
    app = MasterApp(config_defaults=config.get_default_config())
    try:
        setup_and_run(app)
    finally:
        app.close()
      
        
if __name__ == "__main__":
    main()

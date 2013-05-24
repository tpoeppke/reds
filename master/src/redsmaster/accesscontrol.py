# coding=utf-8
"""This module implements the core role-based access control model, 
but without explicit sessions.

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


import functools
import os
import stat
import base64

from sqlalchemy import exc as alexc, create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from passlib.apps import custom_app_context as pwd_context

from redsmaster import exc, util
from redsmaster.model import (Base, RBACUser, RBACRole, RBACPermission, 
                              RBACOperation, RBACObject, RBACAuthCredential,
                              RedsRepository)

def needs_database(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.initialised:
            raise exc.DatabaseError("Database is not initialised!")
        else:
            return func(self, *args, **kwargs)
    return wrapper


class AccessManager(object):
    """The generic AccessManager for the RBAC model."""
    
    def __init__(self):
        self._database = None
        self._engine = None
        self._Session = None
        self.initialised = False
        
    def close(self):
        """
        Close the connection to the database.
        """
        if not self.initialised:
            return
        
        self._Session.close_all() 
        self._engine.dispose()
        self.initialised = False
        del self._Session 
        del self._engine

    
    def _get_object_by_name(self, cls, name):
        obj = self._Session.query(cls).filter_by(name = name).first()
        if obj is None:
            raise exc.DatabaseError("Object '%s' doesn't exist!" % name)
        return obj
    
    def _get_object_by_filter(self, cls, **objfilter):
        obj = self._Session.query(cls).filter_by(**objfilter).first()
        if obj is None:
            raise exc.DatabaseError("Object with attributes '%s' "
                                    "doesn't exist!" % objfilter)
        return obj
    
    def _get_or_create(self, cls, name):
        obj = self._get_object_by_name(cls, name)
        if obj is None:
            obj = cls(name=name)
            self._commit_add(obj)
        return obj
    
    def _commit_add(self, obj):
        self._Session.add(obj)
        try:
            self._Session.commit()
        except alexc.SQLAlchemyError as err:
            self._Session.rollback()
            raise exc.DatabaseError("Could not add object to database. "
                                    "Reason: %s" % err)
        
    def _commit_del(self, obj):
        try:
            self._Session.delete(obj)
            self._Session.commit()
        except alexc.SQLAlchemyError as err:
            self._Session.rollback()
            raise exc.DatabaseError("Could not delete object from database. "
                                    "Reason: %s" % err)
        
    
    ########################################
    #
    # Administrative functions
    #
    ########################################
        
    def _create_new_user(self, name, **kw):
        """ 
        Template method for subclasses. This way we can support
        subclasses of RBACUser too.
        """
        raise NotImplementedError("Not implemented!")
    
    def _create_new_role(self, name, **kw):
        """ 
        Template method for subclasses. This way we can support
        subclasses of RBACRole too.
        """
        raise NotImplementedError("Not implemented!")
    
    def _create_new_credential(self, username, cred_type, content, **kw):
        """
        Template method for subclasses. This way we can support
        subclasses of RBACCredential too.
        """
        raise NotImplementedError("Not implemented!")
    
    def _create_new_object(self, name, **kw):
        """ 
        Template method for subclasses. This way we can support
        subclasses of RBACObject too.
        """
        raise NotImplementedError("Not implemented!")
        
    @needs_database
    def add_user(self, name, **kw):
        """Adds a new user to the database."""
        try:
            self._get_object_by_name(RBACUser, name)
        except exc.DatabaseError:
            new_user = self._create_new_user(name, **kw)
            self._commit_add(new_user)
        else:
            raise exc.DatabaseError("User already exists!")
    
    @needs_database
    def del_user(self, name):
        """Deletes an existing user from the database."""
        user = self._get_object_by_name(RBACUser, name)
        self._commit_del(user)
    
    @needs_database
    def add_role(self, name, **kw):
        """Adds a new role to the database."""
        try: 
            self._get_object_by_name(RBACRole, name)
        except exc.DatabaseError:
            new_role = self._create_new_role(name, **kw)
            self._commit_add(new_role)
        else:
            raise exc.DatabaseError("Role already exists!")
        
    @needs_database
    def del_role(self, name):
        """Deletes a role from the database"""
        user = self._get_object_by_name(RBACRole, name)
        self._commit_del(user)
    
    @needs_database
    def assign_user(self, username, rolename):
        """Assigns the user with username to the role with rolename."""
        user = self._get_object_by_name(RBACUser, username)
        role = self._get_object_by_name(RBACRole, rolename)
        if role not in self.assigned_roles(user.name):
            user.roles.append(role)
            self._Session.commit()
        else:
            raise exc.DatabaseError("User already assigned to this role!")
    
    @needs_database
    def deassign_user(self, username, rolename):
        """Deassigns the user with username from the role with rolename."""
        user = self._get_object_by_name(RBACUser, username)
        role = self._get_object_by_name(RBACRole, rolename)
        if role in self.assigned_roles(user.name):
            user.roles.remove(role)
            self._Session.commit()
        else:
            raise exc.DatabaseError("User '%s' is not assigned to "
                                        "the role '%s'!" % (username, rolename))
    @needs_database    
    def assign_auth_credential(self, username, cred_content, cred_type):
        """
        Assigns the given credentials to the user with username.
        The cred_type defines how the cred_content is to be handled.  
        """
        user = self._get_object_by_name(RBACUser, username)
        credential_filter = dict(content=cred_content, type=cred_type)
        try:
            credential = self._get_object_by_filter(RBACAuthCredential, 
                                                    **credential_filter)
            raise exc.DatabaseError("Credential is already in use!")
        except exc.DatabaseError:
            credential = self._create_new_credential(username=username, 
                                                     content=cred_content, 
                                                     cred_type=cred_type)
        
        user.auth_credentials.append(credential)
        self._commit_add(user)
        
    @needs_database
    def deassign_auth_credential(self, username, cred_type, cred_content):
        """Deassigns the given credentials from the user with username."""
        user = self._get_object_by_name(RBACUser, username)
        credential_filter = dict(content=cred_content, type=cred_type)
        credential = self._get_object_by_filter(RBACAuthCredential, 
                                                **credential_filter)
        
        user.auth_credentials.remove(credential)
        self._commit_add(user)
    
    def _get_permission_tuple(self, operationname, objectname, 
                              create_obj=False):
        operation = self._get_object_by_name(RBACOperation, operationname)
        try:
            obj = self._get_object_by_name(RBACObject, objectname)
        except exc.DatabaseError:
            if create_obj:
                obj = self._create_new_object(name=objectname)
                self._commit_add(obj)
            else:
                raise
        return operation, obj
    
    @needs_database
    def grant_permission(self, operationname, objectname, rolename):
        """
        Grants the role the permission defined by operationname and objectname.
        """
        operation, obj = self._get_permission_tuple(operationname, objectname, 
                                                    create_obj=True)
        role = self._get_object_by_name(RBACRole, rolename)
        
        objfilter = dict(operation=operation, obj=obj)
        try:
            permission = self._get_object_by_filter(RBACPermission, **objfilter)
        except exc.DatabaseError:
            permission = RBACPermission(operation=operation, obj=obj)
        
        role.permissions.append(permission)
        self._commit_add(permission)
    
    @needs_database
    def revoke_permission(self, operationname, objectname, rolename):
        """Revokes the permission from the given role."""
        operation, obj = self._get_permission_tuple(operationname, objectname)
        role = self._get_object_by_name(RBACRole, rolename)
        objfilter = dict(operation=operation, obj=obj)
        permission = self._get_object_by_filter(RBACPermission, **objfilter)
            
        role.permissions.remove(permission)
        self._commit_del(permission)
        
    
    ########################################
    #
    # System functions
    #
    ########################################
    
    @needs_database
    def check_access(self, username, operationname, objectname):
        """
        Checks whether the user with username has the permission 
        defined by operationname and objectname
        """
        operation = self._get_object_by_name(RBACOperation, operationname)
        available_operations = self.user_operations_on_object(username, 
                                                              objectname)
        return operation in available_operations
        
    
    
    ########################################
    #
    # Review functions
    #
    ########################################
    
    @needs_database
    def assigned_users(self, rolename):
        """Returns the users assigned to the given role."""
        role = self._get_object_by_name(RBACRole, rolename)
        return role.users
    
    @needs_database
    def assigned_roles(self, username):
        """Returns the roles assigned to the given username."""
        user = self._get_object_by_name(RBACUser, username)
        return user.roles
    
    @needs_database
    def assigned_auth_credentials(self, username, cred_type):
        """
        Returns the assigned credentials of the specified type of the user.
        """
        user = self._get_object_by_name(RBACUser, username)
        creds = [cred for cred in user.auth_credentials\
                 if cred.type == cred_type]
        return creds
    
    @needs_database
    def role_permissions(self, rolename):
        """Returns the permissions assigned to the given role."""
        role = self._get_object_by_name(RBACRole, rolename)
        return role.permissions
    
    @needs_database
    def user_permissions(self, username):
        """Returns the permissions assigned to the given user."""
        user = self._get_object_by_name(RBACUser, username)
        
        permissions = []
        for role in user.roles:
            role_permissions = [permission for permission in role.permissions]
            permissions.extend(role_permissions)
        return permissions
    
    @needs_database
    def role_operations_on_object(self, rolename, objectname):
        """
        Returns the operations permitted to the given role on the given object.
        """
        role = self._get_object_by_name(RBACRole, rolename)
        obj = self._get_object_by_name(RBACObject, objectname)
        
        return self._Session.query(RBACOperation).\
                    join((RBACPermission, RBACOperation.permissions)).\
                    join((RBACRole, RBACPermission.roles)).\
                    filter(RBACPermission.obj == obj,
                           RBACRole.name == role.name).all()
    
    @needs_database
    def user_operations_on_object(self, username, objectname):
        """
        Returns the operations permitted to the given user on the given object.
        """
        user = self._get_object_by_name(RBACUser, username)
        obj = self._get_object_by_name(RBACObject, objectname)
        return self._Session.query(RBACOperation).\
                    join((RBACPermission, RBACOperation.permissions)).\
                    join((RBACRole, RBACPermission.roles)).\
                    join((RBACUser, RBACRole.users)).\
                    filter(RBACPermission.obj == obj, 
                           RBACUser.name == user.name).all()
    
    
REDS_OPERATIONS = [u'repo.read',
                   u'repo.write',
                   u'repo.create',
                   u'admin.repos',
                   u'admin.usermanagement']


REDS_DEFAULT_USERS = [u'guest',
                      u'admin']


REDS_DEFAULT_PASSWORDS = [(u'guest', u''),
                          (u'admin', u'')]


REDS_DEFAULT_ROLES = [u'guests',
                      u'admins']


REDS_DEFAULT_ASSOC = [(u'guest', u'guests'),
                      (u'admin', u'admins')]


REDS_DEFAULT_PERMISSIONS = [(u'admins', u'', u'admin.usermanagement'),
                            (u'admins', u'', u'repo.create'),
                            (u'admins', u'', u'admin.repos')]


class RedsAccessManager(AccessManager):
    """
    AccessManager implementation for reds. 
    Uses repositories instead of generic objects.
    """
    
    def __init__(self):
        super(RedsAccessManager, self).__init__()
        self.app = None
        self.command_map = {
                            "adduser": self.add_user,
                            "deluser": self.del_user,
                            "addrole": self.add_role,
                            "delrole": self.del_role,
                            "assignuser": self.assign_user,
                            "deassignuser": self.deassign_user,
                            "assignauthcred": self.assign_auth_credential,
                            "deassignauthcred": self.deassign_auth_credential,
                            "grantpermission": self.grant_permission,
                            "revokepermission": self.revoke_permission
                            } 
        
    @property
    def users_with_pw(self):
        users = self._Session.query(RBACUser).\
                    join((RBACAuthCredential, RBACUser.auth_credentials)).\
                    filter(RBACAuthCredential.type=="password").all()
        return [user.name for user in users]
                
    @property
    @needs_database
    def engine(self):
        return self._engine
    
    def setup(self, app_obj, database=None):
        """
        Makes sure that AccessManager is ready to receive further 
        requests.
        
        Initialise the database connection and establish a session that can
        be used to interact with it. 
        """
        
        self.app = app_obj
        if database is None:
            database = self._get_database_path()
        self._database = "sqlite:///" + database
            
        self._engine = create_engine(self._database)
        self._Session = scoped_session(sessionmaker(autoflush=True,
                                                    autocommit=False,
                                                    bind=self._engine)
                                       )
        self.initialised = True
        
    def initial_setup(self, app_obj, database=None):
        """
        Set up the AccessManager with a default configuration of users, 
        roles and permissions.
        
        Create a database if none exists and add standard users and/or roles.
        This function also adds the available operations to the database.
        It also calls the setup function so that after  
        initial_setup the AccessManager object is ready for use.
        """
        
        self.app = app_obj
        if database is None:
            path = self._get_database_path()
        else:
            path = database
            
        if database is not None and not database.startswith(":"):
            try:
                with open(name=path, mode='w'):
                    pass
                os.chmod(path, self._get_database_mode())
            
            except IOError as err:
                raise exc.DatabaseError(u"Could not create the user database "
                                        "file!\nReason:\n%s" % err)
            
        self.setup(self.app, database)
        Base.metadata.create_all(self._engine)
        self._setup_default_content()
        
    def is_accesscontrol_cmd(self, split_command):
        """
        Checks whether the given split_command is one of the possible 
        accesscontrol commands.
        """
        try:
            self.command_map[split_command[0]]
        except KeyError:
            return False
        return True
        
        
    def admin_operations(self, username):
        """
        Returns all operations available to the username that contain 
        the word 'admin'.
        """
        return self._Session.query(RBACOperation).\
                    join((RBACPermission, RBACOperation.permissions)).\
                    join((RBACRole, RBACPermission.roles)).\
                    join((RBACUser, RBACRole.users)).\
                    filter(RBACUser.name == username,
                           RBACOperation.name.contains('admin.')).all()
        
    @needs_database
    def check_access(self, username, operationname, objectname):
        operation = self._get_object_by_name(RBACOperation, operationname)
        available_operations = self.user_operations_on_object(username, 
                                                              objectname)
        
        # The admin.repos operation is allowed on the top repo
        admin_repo = self.admin_operations(username)
        available_operations.extend(admin_repo)
        
        if operation in available_operations:
            return True
        elif operation.name.startswith("repo"):
            admin_operation = self._get_object_by_name(RBACOperation, 
                                                   name="admin.repos")
            # Allow repository admins access to all repositories
            if admin_operation in available_operations:
                return True
            
            write_operation = self._get_object_by_name(RBACOperation, 
                                                       "repo.write")
            # Write permissions on a repository include read permissions
            if (operation.name == "repo.read") and \
                (write_operation in available_operations):
                return True
        return False
        
    def assign_auth_credential(self, username, cred_content, cred_type):
        # Overwrite super to check that only one password is set per user
        if cred_type == 'password':
            if username in self.users_with_pw:
                user = self._get_object_by_name(RBACUser, username)
                # Delete the old password first
                objfilter = dict(user=user, type=cred_type)
                cred = self._get_object_by_filter(RBACAuthCredential, 
                                                  **objfilter)
                self._commit_del(cred)
            
        super(RedsAccessManager, self).assign_auth_credential(username, 
                                                              cred_content, 
                                                              cred_type)
        
        
    def add_repo(self, repo):
        self._commit_add(repo)
            
    def del_repo(self, reponame):
        repo = self._get_object_by_name(RedsRepository, reponame)
        self._commit_del(repo)
    
    def _get_database_path(self):
        mountpoint = self.app.configmanager.get_option('mountpoint')
        db_file = os.path.join(mountpoint, 'users.db')
        return db_file
    
    @staticmethod
    def _get_database_mode():
        return stat.S_IRUSR | stat.S_IWUSR

    def _create_default_users(self):
        for username in REDS_DEFAULT_USERS:
            self.add_user(username)

    def _create_default_roles(self):
        for rolename in REDS_DEFAULT_ROLES:
            self.add_role(rolename)

    def _create_default_associations(self):
        for username, rolename in REDS_DEFAULT_ASSOC:
            self.assign_user(username, rolename)

    def _create_default_permissions(self):
        for rolename, objectname, operationname in REDS_DEFAULT_PERMISSIONS:
            self.grant_permission(operationname, objectname, rolename)

    def _create_default_credentials(self):
        for username, credential in REDS_DEFAULT_PASSWORDS:
            self.assign_auth_credential(username, credential, "password")

    def _setup_default_content(self):
        self._create_available_operations()
        self._create_default_users()
        self._create_default_roles()
        self._create_default_associations()
        self._create_default_permissions()
        self._create_default_credentials()
        
    def _create_available_operations(self):
        for operation in REDS_OPERATIONS:
            database_op = RBACOperation(name=operation)
            self._commit_add(database_op)
        
    def _create_new_role(self, name, **kw):
        return RBACRole(name=name, **kw)
    
    def _create_new_user(self, name, **kw):
        return RBACUser(name=name, **kw)
    
    def _create_new_object(self, name, **kw):
        # Use the name of the repository as its path
        util.safe_path(name)
        return self.app.versioncontrol.new_repository(path=name, **kw)
    
    def _create_new_credential(self, username, cred_type, content, **kw): 
        if cred_type == "password":
            content = pwd_context.encrypt(content)
        elif cred_type == 'publickey':
            content = base64.encodestring(content)
        else:
            raise exc.DatabaseError("Credential type %s is not supported", 
                                    cred_type)
        return RBACAuthCredential(type=cred_type, content=content)


# coding=utf-8
"""This file contains the model definitions for the accesscontrol database.

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


from sqlalchemy import Table, Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

def _many_to_many_table(first_table, second_table, base):
    return Table(first_table + "_" + second_table, base.metadata,
                Column(first_table + "_id", Integer, 
                       ForeignKey(first_table + ".id"), primary_key=True),
                Column(second_table + "_id", Integer,
                       ForeignKey(second_table + ".id"), primary_key=True))
    
    
class BaseMixin(object):
    
    id = Column(Integer, primary_key=True)
    

class UniqueNameMixin(object):
    
    name = Column(String(100), unique=True)
    desc = Column(String(300))
    
        
class RBACUser(BaseMixin, UniqueNameMixin, Base):
    
    __tablename__ = "users"
    fullname = Column(String(100))

    roles = relationship("RBACRole", 
                         secondary=_many_to_many_table("users", "roles", Base),
                         backref="users")
    
    
class RBACAuthCredential(BaseMixin, Base):
    __tablename__ = "auth_credentials"
    
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("RBACUser", backref="auth_credentials")
    
    type = Column(String(50))
    
    content = Column(String)
                

class RBACRole(BaseMixin, UniqueNameMixin, Base):
    
    __tablename__ = "roles"
    
    permissions = relationship("RBACPermission",
                               secondary=_many_to_many_table("roles", 
                                                             "permissions", 
                                                             Base),
                               backref="roles")


class RBACOperation(BaseMixin, UniqueNameMixin, Base):
    
    __tablename__ = "operations"


class RBACObject(BaseMixin, UniqueNameMixin, Base):
    
    __tablename__ = "objects"
    
    type = Column(String(50))
    
    __mapper_args__ = {
        'polymorphic_on':type,
        'polymorphic_identity':'object'
    }


class RBACPermission(BaseMixin, Base):
    
    __tablename__ = "permissions"
    
    operation_id = Column(Integer, ForeignKey("operations.id"))
    operation = relationship("RBACOperation", backref="permissions")
    
    obj_id = Column(Integer, ForeignKey("objects.id"))
    obj = relationship("RBACObject", backref="permissions")
    

class RedsRepository(RBACObject):
    __mapper_args__ = {
        'polymorphic_identity':'redsrepository'
    }
        
    def setup(self):
        """Set up the repository for use.
        
        In this method everything like config files or hooks for the 
        vcs should be created. 
        
        Subclasses must implement this Method.
        
        """
        raise NotImplementedError("Must be implemented in subclass!")
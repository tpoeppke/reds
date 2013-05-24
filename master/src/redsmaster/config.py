# coding=utf-8
"""The configuration module for redsmaster.

All default configuration options are defined here. 

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

from redsmaster import util, log

LOG = log.get_logger("config")

CACHE_DIR = os.path.expanduser("~/.redsmaster/")


class Option(object):
        
    DEFAULT_ARG_OPTIONS = {}
    
    OPTIONS = {}
    
    def __init__(self, name, sanitizer=str, short_name=None, positional=False, 
                 section=None, default=None, **opts):
        super(Option, self).__init__()
        self.name = name
        self.short_name = short_name
        self.positional = positional
        self.section = section
        self.sanitizer = sanitizer
        self._default = default
        self.opts = opts
        
    @property
    def default(self):
        if self._default:
            return self._default
        else:
            return ''
        
    def add_def_dict(self, def_dict):
        if self.section is None:
            def_dict[self.name] = self.default
        else:
            sect = def_dict.get(self.section, dict())
            sect[self.name] = self.default
            def_dict[self.section] = sect
            
    def get_arg(self):
        arg_names = []
        if not self.positional:
            arg_names = ["--%s" % self.name]
            if self.short_name is not None and len(self.short_name) == 1:
                arg_names.append("-%s" % self.short_name)
        else:
            arg_names.append("%s" % self.name)
            
        # Don't include defaults here because the argument defaults would 
        # overwrite the options in the config files.  
        return arg_names, self.opts
            
    def add_option(self, parser):
        arg = self.get_arg()
        parser.add_argument(arg[0], arg[1])
        
    def sanitize(self, value):
        sane_value = self.sanitizer(value)
        if not sane_value:
            sane_value = self.default
        return sane_value
            
        
options = Option.OPTIONS
default_options = Option.DEFAULT_ARG_OPTIONS


def get_default_args():
    ret = [option.get_arg() for option in default_options.values()]
    return ret
    
        
def register_default_option(name, short_name=None, positional=False, 
                            section=None, **kw):
    
    options[name] = Option(name=name, short_name=short_name, 
                           positional=positional, section=section, **kw)
    default_options[name] = options[name]
    
    
def register_option(name, short_name=None, positional=False, 
                    section=None, **kw):
    
    Option.OPTIONS[name] = Option(name=name, short_name=short_name, 
                           positional=positional, section=section, **kw)
    
    
def get_default_config():
    """Collect the default values for a new configuration.
    
    Returns a dictionary with the default configuration data.
    
    """
    def_dict = dict()
    for option in options.values():
        option.add_def_dict(def_dict)
    return def_dict


class ConfigManager(object):
    def __init__(self, app_obj):
        self.app = app_obj
        
    def get_option(self, optionname, quiet=True, default=None):
        value = None
        try:
            option = options[optionname]
            value = self.app.config.get(option.section, 
                                       optionname)
        except KeyError:
            if not quiet:
                raise
            else:
                return default
        
        try:
            if option.action in ["store_true"]:
                value = value[0].upper() == "T" or value =="1" 
            else:
                value = option.sanitize(value)
        except AttributeError:
            pass
        return value
                           
    def set_option(self, optionname, value, quiet=True):
        try:
            option = options[optionname]
            try:
                value = option.sanitize(value)
            except AttributeError:
                pass
        
            self.app.config.set(options[optionname].section, 
                               option.name, value)
        except KeyError:
            if not quiet:
                raise
        
    def read_configfile_from_args(self):
        """
        Read the configuration file if one was given as a command line argument.
        
        The configuration file is read through the config handler of app_obj.
        """
        # Kind of a hack because cement doesn't support parsing a config file 
        # from the command line arguments. 
        cfg_file = self.app.pargs.configfile
        if cfg_file:
            try:
                self.app.config.parse_file(cfg_file)
            except (OSError, IOError):
                pass
                    
    def sanitize_config(self):
        for option in options.values():
            try:
                value = self.app.config.get(option.section, option.name)
                value = option.sanitize(value)
                self.app.config.set(option.section, option.name, value)
            except KeyError:
                LOG.debug("Could not sanitize option '%s.%s'" % (option.section,
                                                                 option.name))
            
    def setup_config(self):
        self.read_configfile_from_args()
        self.sanitize_config()


register_default_option(name="configfile", sanitizer=util.safe_path, 
            section="paths", action="store",
            default=os.path.expanduser("~/.redsmaster/redsmaster.conf"),
            short_name="f", metavar="<path>", help=("The path to the "
            "configuration file. Default: ~/.redsmaster/redsmaster.conf"))


register_default_option(name="authfile", sanitizer=util.safe_path, 
            section="paths", action="store",
            default=os.path.expanduser("~/.redsmaster/authfile"),
            short_name="a", metavar="<path>", help=("The path to the "
            "authentication file. If there is an authentication file, " 
            "the credentials in this file are used for accessing the storage. "
            "Default: ~/.redsmaster/authfile"))


register_option(name="serverlog", sanitizer=util.safe_path, 
            section="log", action="store",
            default=os.path.expanduser("~/.redsmaster/server.log"),
            short_name="l", metavar="<path>", help=("The path to the "
            "file for logging access information."
            "Default: ~/.redsmaster/server.log"))


register_option(name="mountpoint", sanitizer=util.safe_path,  
            section="paths", action="store",
            default="/var/tmp/redsmaster/", metavar="<path>", 
            help=("Mount the storage at this location. " 
            "Default: /var/tmp/redsmaster"))


register_option(name="repodir", sanitizer=util.safe_path,  
            section="paths", action="store",
            default="repos/", metavar="<path>", 
            help=("Create the repositories under this directory inside "
            "the mountpoint. Default: <mountpoint>/repos/"))


register_option(name="storage-url", section="storage", positional=True,
                help="The url to the storage.")


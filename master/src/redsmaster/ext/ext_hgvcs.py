# coding=utf-8
"""
This extension provides the interface for the mercurial versioncontrol system. 

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
import shutil
import pkg_resources

from cement.core import handler
import hglib

from redsmaster import versioncontrol, config, model, exc, util, log

LOG = log.get_logger("hgvcs")

HG_CMD_MAPPING = {'serve-hg': ['hg', '-R', 'repo', 'serve', '--stdio'],
                  'serve-reds': ['hg', '-R', 'repo', 'serve', '--cmdserver',
                                 'pipe', '--config', 'ui.interactive=True'],
                  'init-repo': ['setup_repository', 'repo']}

FILEPATH = pkg_resources.resource_filename("hgextensions", 
                                           "commitsigs/hgredsdeny.py")

class HgHandler(versioncontrol.VersionControlHandler):
    block_write_cmd = ['--config', 'hooks.pretxnchangegroup.redsdeny='
                       'python:%s:deny_write_hook' % FILEPATH]
    
    class Meta:
        label = "mercurialvcs"
        interface = versioncontrol.IVersionControl
    
    def __init__(self):
        super(HgHandler, self).__init__()
        self._client = None
        
    def _setup(self, app_obj):
        super(HgHandler, self)._setup(app_obj)
    
    def setup_repository(self, path):
        repo = self.new_repository(path)
        LOG.debug("Setting up the repository at %s", repo.name)
        repos_path = self.get_repos_path()
        os.chdir(repos_path)
        try:
            hglib.init(repo.name)
        except hglib.error.CommandError as err:
            raise exc.VersionControlError(str(err))
        repo.setup()
        LOG.debug("Trying to add the repo to accessmanager")
        self.app.accessmanager.add_repo(repo)
        LOG.debug("Repo is now ready.")
        
    @staticmethod
    def new_repository(path):
        repo = HgRepository(name=path)
        return repo
    
    @staticmethod
    def is_versioncontrol_command(command):
        LOG.debug("Examining command %s", command)
        if command[0] == "hg":
            return True
        return False
    
    def get_needed_permission(self, command):
        operation = None
        repo = ""
        
        # Only serve and init are supported  
        if "-R" in command and "serve" in command:
            operation = 'repo.read'
        elif "init" in command:
            operation = 'repo.create'
        else:
            raise exc.VersionControlError("Tried to get the permission for an "
                                          "unsupported command.")
        
        if operation == 'repo.read':
            repo = self._extract_repopath(command)
        return operation, repo
    
    def get_sane_command(self, username, command, repopath):
        LOG.debug("Trying to sanitize command.")
        cmd = self._get_vcs_command(command)
        sane_cmd = HG_CMD_MAPPING[cmd]
        internal = False
        
        LOG.debug("Checking command.")
        if cmd.startswith("serve"):
            LOG.debug("Found external command %s with repo %s", sane_cmd, 
                      repopath)
            
            if not self.app.accessmanager.check_access(username=username, 
                                                    objectname=repopath, 
                                                    operationname='repo.write'):
                LOG.debug("User has no write permission.")
                sane_cmd.extend(self.block_write_cmd)
            LOG.debug("Exchanging repo")
            sane_cmd[2] = repopath
            
        if cmd == "init-repo":
            LOG.debug("Found init repo.")
            sane_cmd[0] = self.setup_repository
            sane_cmd[1] = self._extract_repopath(command)
            internal = True
            LOG.debug("Found internal command %s", sane_cmd)
        
        LOG.debug("Command sanitized")
        return sane_cmd, internal
    
    @staticmethod    
    def _get_vcs_command(command):
        LOG.debug("Getting command.")
        if "init" in command:
            LOG.debug("Found init command.")
            return 'init-repo'
        
        if "serve" in command:
            LOG.debug("Found server command.")
            if "--stdio" in command:
                return "serve-hg"
            if "--cmdserver" in command:
                return "serve-reds"
        raise exc.VersionControlError("No supported command found!")
            
        
    @staticmethod
    def _extract_repopath(command):
        repoindex = None
        
        try:
            index = command.index(u"-R")
            if index > 0:
                repoindex = index + 1
        except ValueError:
            try:
                if command.index(u"init") == 1:
                    repoindex = 2
            except ValueError:
                raise exc.VersionControlError("Can't find a repository in "
                "the command '%s'." % command)
        
        repo = util.safe_path(command[repoindex])
        if repo.endswith("/"):
            repo = repo.rstrip("/")
        LOG.debug("Extracted repo is '%s'", repo)
        return repo
        
        
    @property
    def client(self):
        if not self._client:
            self._client = hglib.open(self.get_repos_path())
        return self._client
    
    
class HgRepository(model.RedsRepository):
    __mapper_args__ = {
        'polymorphic_identity':'hgrepository'
    }
    
    def setup(self):
        LOG.debug("Copying hgrc to new repo...")
        
        hgrc_tmpl = pkg_resources.resource_filename("redsmaster", 
                                                    "templates/hgrc.tmpl")
        commitsigs_path = pkg_resources.resource_filename("hgextensions",
                                                    "commitsigs/commitsigs.py")
        
        LOG.debug("Path to commitsigs extension: '%s'", commitsigs_path)
        extension_sect = "\n[extensions]\ncommitsigs = %s" % commitsigs_path
        
        repo_hgrc = os.path.join(self.name, ".hg", "hgrc")
        shutil.copyfile(hgrc_tmpl, repo_hgrc)
        
        with open(repo_hgrc, "a") as new_hgrc:
            new_hgrc.write(extension_sect)

        LOG.debug("Done copying.")
        
    
config.register_option(name="hg-path", section="paths", default="", 
                       action="store", metavar="<path>", 
                       sanitizer=util.safe_path, 
                       help="""Path to hg.""")
        
        
def load():
    handler.register(HgHandler)

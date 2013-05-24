# coding=utf-8
"""This extension provides an SSH servermanager.

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

import socket
import threading
import select
import base64
import traceback
import os

import paramiko
from cement.core import handler, exc as cementexc
from passlib.apps import custom_app_context as pwd_context

from redsmaster import (server, config, util, command as pipe, exc, 
                        log)

SERVERLOG = log.SERVERLOG
LOG = log.get_logger("sshserver")

class NegotiationError(exc.ServerError):
    """Raised if SSH Negotiation failed"""
    
class CalledProcessError(exc.ServerError):
    """Raised if a proccess executed by the server raises an error."""

class AuthenticatedClientConnection(threading.Thread):
    def __init__(self, username, channel, command, addr, workingdir, event, 
                 internal_cmd=False):
        super(AuthenticatedClientConnection, self).__init__()
        self.channel = channel
        self.command = command
        self.username = username
        self.addr = addr
        self.workingdir = workingdir
        self.internal_cmd = internal_cmd
        self.event = event
        
    def _redirect_chan_to_process(self, proc):
        empty_ctr = 0
        while empty_ctr <= 5:
            if self.channel.exit_status_ready():
                break
            
            read, write, oob = select.select(
                                    [self.channel, proc.stdout, proc.stderr], 
                                    [], [], 10)
            
            if self.channel in read:
                data = self.channel.recv(1024)
                if data:
                    #SERVERLOG.debug("Data to proc input: %s", data)
                    proc.stdin.write(data)
                    proc.stdin.flush()
                    empty_ctr = 0
                else:
                    #SERVERLOG.debug("No data. Increasing counter")
                    empty_ctr += 1                    

            if proc.stdout in read:
                data = proc.stdout.read(1)
                if data:
                    #SERVERLOG.debug("Data from process: %s", data)
                    self.channel.sendall(data)

            if proc.stderr in read:
                data = proc.stderr.read(1)
                if data:
                    #SERVERLOG.debug("Error from process: %s", data)
                    self.channel.sendall_stderr(data)
                else:
                    break
            
            if read == False and write == False and oob == False:
                SERVERLOG.info("Connection timed out.")
                break
                
    def _get_process(self):
        cmd = pipe.Command(self.command[0])
        args = self.command[1:]
        
        proc = cmd.get_pipe(*args)
        return proc

    def run(self):
        SERVERLOG.info("User '%s' executes command '%s'", self.username, 
                       self.command)
        try:
            os.chdir(self.workingdir)
        
            if self.internal_cmd:
                # Internal commands can be executed as python functions 
                self.command[0](*self.command[1:])
                self.channel.send_exit_status(0)
            else:
                proc = self._get_process()
        
                SERVERLOG.debug("Redirecting channel to process...")
                try:
                    self._redirect_chan_to_process(proc)
                except exc.RedsError as err:
                    self.channel.sendall_stderr(str(err))
                
                SERVERLOG.info("Command successfully run. Closing "
                           "the connection.\r\n")
            
        except Exception as err:
            SERVERLOG.info("Exception while executing: %s:\n%s", err, 
                           traceback.print_exc())
            try:
                self.channel.sendall_stderr(err)
            except Exception:
                pass
        finally:
            if not self.internal_cmd:
                try:
                    out, err = proc.communicate()
                    if err:
                        SERVERLOG.debug("Error from process: %s", err)
                        self.channel.sendall_stderr(err)
                    if out:
                        self.channel.sendall(out)
                except Exception:
                    pass
                else:
                    self.channel.sendall("Command successfully run!")
                
            SERVERLOG.debug("Signaling server...")
            self.event.set()
            SERVERLOG.info("Client '%s:%s' disconnected from process.", 
                           self.addr[0], self.addr[1])


class SetupClientConnectionThread(threading.Thread):
    def __init__(self, sock, addr, host_key, app):
        super(SetupClientConnectionThread, self).__init__()
        self.socket = sock
        self.host_key = host_key
        self.addr = addr
        self.app = app
        
    def _get_new_server(self, transport):
        SERVERLOG.debug("Adding hostkey to transport.")
        transport.add_server_key(self.host_key)
        sshserver = SSHServer(self.app)
            
        try:
            SERVERLOG.debug("Trying to start server.")
            try:
                transport.start_server(server=sshserver)
            except EOFError as err:
                SERVERLOG.error("EOFError: %s", traceback.print_exc())
                raise
        except paramiko.SSHException as err:
            raise NegotiationError("SSH negotiation with client '%s:%s' "
                                   "failed. Reason: %s" % (self.addr[0], 
                                                           self.addr[1], err))
        return sshserver
            
    def _create_channel(self, transport):
        """Wait for the client to authenticate.
        
        Raises an AuthenticationError if authentication failed.
        """
        chan = transport.accept(20)
        if chan is None:
            msg = "Authentication failed for client '%s:%s'." % (self.addr[0], 
                                                                 self.addr[1])
            SERVERLOG.debug(msg)
            raise exc.AuthenticationError(msg)
    
    def _wait_for_client_request(self, sshserver):
        """Wait for the client to issue a request."""
        if not sshserver.requestevent.wait(10):
            raise exc.TimeoutError("Timeout for client '%s'. "
                                   "No valid request was made." % self.addr[0], 
                                   self.addr[1])
        
    def run(self):
        try:
            SERVERLOG.info("Setting up the client socket...")
            transport = paramiko.Transport(self.socket)
            
            try:
                transport.load_server_moduli()
            except:
                SERVERLOG.error("Failed to load moduli")
                raise
            
            SERVERLOG.debug("Creating server for '%s:%s'...", self.addr[0], 
                           self.addr[1])
            sshserver = self._get_new_server(transport)
            
            SERVERLOG.debug("Creating communication channel for '%s:%s'...", 
                           self.addr[0], self.addr[1])
            self._create_channel(transport)
            
            SERVERLOG.debug("Waiting for client request from '%s:%s'...", 
                           self.addr[0], self.addr[1])
            self._wait_for_client_request(sshserver)
            
            SERVERLOG.debug("Waiting for the client '%s' to disconnect...",
                            self.addr)
            sshserver.closeevent.wait()
            
        except Exception as err:
            SERVERLOG.error("Caught exception: %s: %s\n", err.__class__, err)
        finally:
            # Close the transport object if there is one
            transport.close()
            SERVERLOG.info("Connection with '%s:%s' closed.", self.addr[0], 
                            self.addr[1])
        
        

class SSHServer(paramiko.ServerInterface):
    def __init__(self, app_obj):
        self.requestevent = threading.Event()
        self.closeevent = threading.Event()
        self.accessmanager = app_obj.accessmanager
        self.username = None
        self.app = app_obj
        
    def check_auth_password(self, username, password):
        SERVERLOG.debug("Trying to authenticate with password...")
        
        if (self.app.configmanager.get_option('allow-pw-auth') and 
            username in self.accessmanager.users_with_pw):
            
            good_password_hash = self.accessmanager.\
                                    assigned_auth_credentials(
                                                    username, 
                                                    cred_type="password"
                                                    )[0].content
            
            if pwd_context.verify(password, good_password_hash):
                SERVERLOG.info("User '%s' logged in with password!", username)
                self.username = username
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
        
    def check_auth_publickey(self, username, key):
        creds = self.accessmanager.assigned_auth_credentials(username, 
                                                             "publickey")
        for credential in creds:
            try:
                SERVERLOG.info("Login attempt with key: %s", 
                               key.get_base64())
                good_key = base64.decodestring(credential.content).split(" ")[1]
                SERVERLOG.debug("Good key: %s", good_key)
            except paramiko.SSHException as err:
                SERVERLOG.error("Error authenticating publickey: %s" , err)
            else:
                if good_key == key.get_base64():
                    self.username = username
                    return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        permitted = "publickey"
        
        if (self.app.configmanager.get_option('allow-pw-auth') and 
            username in self.accessmanager.users_with_pw):
            
            SERVERLOG.debug("Got user with password")
            permitted = "password,publickey"
        return permitted
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def _get_vcs_command(self, split_command):
        command_to_execute = None
        internal = False
        
        operationname, repopath = self.app.versioncontrol.\
                            get_needed_permission(split_command)
        SERVERLOG.debug("Needed permissions are (%s, %s)", operationname, 
                        repopath)
        
        has_access = self.accessmanager.check_access(username=self.username, 
                                                    operationname=operationname,
                                                    objectname=repopath)
        
        if has_access:
            SERVERLOG.debug("User '%s' has the right to execute the "
                            "command.", self.username)
            command_to_execute, internal = self.app.versioncontrol\
                                    .get_sane_command(self.username, 
                                                      split_command,
                                                      repopath)
                                    
        SERVERLOG.debug("Command to execute '%s' and internal is '%s'", 
                        command_to_execute, internal)
        return command_to_execute, internal
    
    def check_channel_exec_request(self, channel, command):
        SERVERLOG.debug("Splitting command")
        
        split_command = command.split(' ')
        command_to_execute = None
        internal = False
        
        workingdir = self.app.versioncontrol.get_repos_path()
        
        vcs = self.app.versioncontrol
        handled_by_vcs = vcs.is_versioncontrol_command(split_command)
        if handled_by_vcs:
            SERVERLOG.debug("Command is handled by versioncontrol.")
            command_to_execute, internal = self._get_vcs_command(split_command)
            SERVERLOG.debug("Command to execute is '%s'.", command_to_execute)
        elif self.accessmanager.check_access(username=self.username, 
                                        operationname="admin.usermanagement",
                                        objectname=""):
            
            SERVERLOG.debug("Usermanager logged in to execute command '%s'.", 
                            command)
            
            try:
                command_to_execute = self.accessmanager.\
                                            command_map[split_command[0]]
            except KeyError:
                pass
            else:
                command_to_execute = [command_to_execute] + split_command[1:]
                internal = True
                SERVERLOG.debug("Executing")
        
        if command_to_execute is not None:
            SERVERLOG.info("Starting thread to execute command '%s' "
                            "for user '%s'.", command_to_execute, 
                                              self.username)
            self.requestevent.set()
            thread = AuthenticatedClientConnection(username=self.username,
                                                   channel=channel, 
                                                   command=command_to_execute, 
                                                   addr=channel.getpeername(), 
                                                   workingdir=workingdir, 
                                                   event=self.closeevent, 
                                                   internal_cmd=internal)
            thread.start()
            return True
        
        channel.sendall_stderr("You don't have the permission to do that!\r\n")
        SERVERLOG.warn("User '%s' was not permitted to execute the "
                       "command '%s'.", self.username, command)
        return False
            
                
    def check_channel_shell_request(self, channel):
        # Right now there is no need for shell access 
        return False
        

class SSHServerManager(server.BaseServerManager):
    class Meta:
        label = "SSHServerManager"
        interface = server.IServerManager
        config_section = "sshserver"
        
    def __init__(self):
        super(SSHServerManager, self).__init__()
        self.host_keyfile = None
        self.host_key = None
        
    def _pre_daemonize(self):
        self.host_keyfile = self.app.configmanager.get_option('host-key')
        SERVERLOG.debug("Trying to get the server hostkey from '%s'.", 
                        self.host_keyfile)
        
        try:
            self.host_key = paramiko.RSAKey(filename=self.host_keyfile)
        
        except paramiko.PasswordRequiredException as err:
            key_pw = util.get_pass("Please enter the password to decrypt "
                                   "the keyfile '%s':" % self.host_keyfile)
            
            self.host_key = paramiko.RSAKey.from_private_key_file(
                                filename=self.host_keyfile, password=key_pw)
            
        except paramiko.SSHException as err:
            SERVERLOG.debug(u"Could not generate the host-key: %s", err)
        
        except IOError:
            file_pw = util.get_pass("Please enter the password to encrypt the "
                                    "new hostkey file: ")
            if file_pw == "":
                file_pw = None
                
            SERVERLOG.info("Creating new keyfile...")
            self._generate_host_key(1024, file_pw)
        
    def _generate_host_key(self, bits, password):
        self.host_key = paramiko.RSAKey.generate(bits)
        try:
            self.host_key.write_private_key_file(self.host_keyfile, 
                                                 password=password)
        except IOError as err:
            raise exc.ServerError(str(err))
        
    @staticmethod
    def _bind_socket(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', port))
        return sock
    
    def _listen_for_connections(self, sock):
        sock.listen(5)
        try:
            while True:
                select.select([sock], [], [])
                try:
                    client, addr = sock.accept()
                    SERVERLOG.info('Connection accepted from %s', addr)
                except Exception as err:
                    SERVERLOG.info('Accept failed: %s\n', err)
                    raise exc.ServerError("Accept failed: %s" % err)
                else:
                    SERVERLOG.debug("Setting up new client connection...")
                    thread = SetupClientConnectionThread(client, addr, 
                                                         self.host_key, 
                                                         self.app)
                    thread.start()
        except exc.TimeoutError as err:
            SERVERLOG.info("%s", err)
        except cementexc.CaughtSignal as sig:
            SERVERLOG.info("%s.", sig)
        except Exception as err:
            SERVERLOG.error("Caught exception: %s", err)
        finally:
            sock.close()
        
    def _run(self):
        port = self.app.configmanager.get_option('port', self.app)
        SERVERLOG.info("Server is listening on port %s...", port)
        
        try:
            sock = self._bind_socket(port)
        except Exception as err:
            SERVERLOG.info('Binding socket failed: %s', err)
            return
            
        SERVERLOG.info('Listening for connections ...')
        self._listen_for_connections(sock)


config.register_option(name="port", sanitizer=util.sane_port,
            section="sshserver", action="store",
            default=2222, metavar="<port>", 
            help="Bind the SSH Server to this port. Default is 2222")


config.register_option(name="host-key", sanitizer=util.safe_path,
            section="sshserver", action="store",
            default=os.path.expanduser("~/.redsmaster/host_key_rsa"), 
            metavar="<path>", help="Use the defined key file as the host key "
            "for the server. Default: ~/.redsmaster/host_key_rsa")

config.register_option(name="allow-pw-auth", section="sshserver", 
            action="store_true", help="Allow users with password to use the "
            "password as SSH Login credentials.")

config.register_option(name="host-key-length", sanitizer=int,
            section="sshserver", action="store",
            default=1024, metavar="<integer>", 
            help="If a host key has to be generated use this length. "
            "Generated host keys are RSA keys by default.")
    

def load():
    handler.register(SSHServerManager)
    
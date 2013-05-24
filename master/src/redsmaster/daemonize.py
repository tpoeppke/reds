# coding=utf-8
"""This module provides basic functionality to start a daemon process.

The functions in this module are based on python-daemon 
by Ben Finney <ben+python@benfinney.id.au>.

"""

import os
import sys

from redsmaster import log

LOG = log.get_logger("daemonize")

def daemonize(workdir='/'):
    '''Daemonize the process'''
    detach_process_context(workdir)

    redirect_stream(sys.stdin, None)
    redirect_stream(sys.stdout, None)
    redirect_stream(sys.stderr, None)


def detach_process_context(workdir):
    """ Detach the process context from parent and session.

        Detach from the parent process and session group, allowing the
        parent to exit while this process continues running.

        Reference: “Advanced Programming in the Unix Environment”,
        section 13.3, by W. Richard Stevens, published 1993 by
        Addison-Wesley.
    
        """
    try:
        pid = os.fork()
        if pid > 0:
            os._exit(0)
    except OSError as err:
        LOG.error("Error forking first child: %s", err)
        sys.exit(1)
        
    os.chdir(workdir)
    os.setsid()
    os.umask(0)
    
    try:
        pid = os.fork()
        if pid > 0:
            LOG.info("Daemon PID is %s", pid)
            os._exit(0)
    except OSError as err:
        LOG.error("Error forking first child: %s", err)
        sys.exit(1)
    
    
def redirect_stream(system_stream, target_stream):
    """ Redirect a system stream to a specified file.

        `system_stream` is a standard system stream such as
        ``sys.stdout``. `target_stream` is an open file object that
        should replace the corresponding system stream object.

        If `target_stream` is ``None``, defaults to opening the
        operating system's null device and using its file descriptor.

        """
    if target_stream is None:
        target_fd = os.open(os.devnull, os.O_RDWR)
    else:
        target_fd = target_stream.fileno()
    os.dup2(target_fd, system_stream.fileno())
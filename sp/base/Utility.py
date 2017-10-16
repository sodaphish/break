"""
@author: sodaphish@protonmail.ch
@date: 2016/07/11
@updated: 2016/12/24

utility functions that don't fall into a class for various reasons.
"""

import subprocess32
import re
import sys
try:
    import ipaddress
except:
    print "missing ipaddress; please `pip install ipaddress` before proceeding"
    sys.exit(2)


def is_ip(target):
    """
    returns false if target is not a valid IP address
    """
    try:
        ipaddress.ip_address(unicode(target))
    except ipaddress.AddressValueError:
        return False
    except ValueError:
        return False
    return True


def is_port(port):
    """
    returns true if the port is within the valid IPv4 range
    """
    if port >= 0 and port <= 65535:
        return True
    return False


def get_cmd_output(*bits):
    """
    function that executes a command and returns a PIPE to the calling function

    NOTE: the output of the cmd can be gotten via retval.communicate() at the 
    calling function.
    """
    args = re.split(' ', bits[0])
    retval = ""
    try:
        # for the record: the documentation for subprocess32.check_calls is
        # pure garbage.
        retval = subprocess32.Popen(
            args, stdout=subprocess32.PIPE, stderr=subprocess32.PIPE)
    except subprocess32.CalledProcessError as e:
        # something happened?
        globals()['log'].critical("process error running `%s`: %s" % (args, e))
        return False
    except subprocess32.TimeoutExpired as e:
        # command hit the timeout while executing
        globals()['log'].critical("timed-out running `%s`: %s" % (args, e))
        return False
    except OSError as e:
        # handle 'file not found'
        globals()['log'].critical("`%s` couldn't be found" % (args))
        return False
    return retval

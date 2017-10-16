"""
@name: DiagInfo.py
@author: sodaphish@protonmail.py
@written: 2016/07/25
@change: 2016/09/17

This is a system diagnostic class.  Currently only works on *nix boxes.
"""

import psutil
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import datetime
import os
import time
import re
import sys

try:
    from sp.base.Utility import get_cmd_output
except Exception as e:
    print "must install sp in sys.path() -- %s" % (e)
    print "email sodaphish@protonmail.ph for a copy of the sp lib"
    sys.exit(2)


class DiagInfo():
    """
    DiagInfo class provides an interface to various system things one might want to know whilst gathering diagnostic information about a system
    """

    # these are internal things that we aren't providing to anyone using the
    # class
    NICS = []
    VOLUMES = []
    AD = "-"
    AF_INET6 = getattr(socket, 'AF_INET6', object())
    PROTO_MAP = {
        (AF_INET, SOCK_STREAM): 'tcp',
        (AF_INET6, SOCK_STREAM): 'tcp6',
        (AF_INET, SOCK_DGRAM): 'udp',
        (AF_INET6, SOCK_DGRAM): 'udp6',
    }
    AF_MAP = {
        socket.AF_INET: 'IPv4',
        socket.AF_INET6: 'IPv6',
        psutil.AF_LINK: 'MAC',
    }
    PROC_STATUSES_RAW = {
        psutil.STATUS_RUNNING: "R",
        psutil.STATUS_SLEEPING: "S",
        psutil.STATUS_DISK_SLEEP: "D",
        psutil.STATUS_STOPPED: "T",
        psutil.STATUS_TRACING_STOP: "t",
        psutil.STATUS_ZOMBIE: "Z",
        psutil.STATUS_DEAD: "X",
        psutil.STATUS_WAKING: "WA",
        psutil.STATUS_IDLE: "I",
        psutil.STATUS_LOCKED: "L",
        psutil.STATUS_WAITING: "W",
    }

    def __init__(self):
        """
        do class instantiation things
        """
        self._get_vols()  # TODO: this should probably be updated periodically
        self._get_nics()

        if hasattr(psutil, 'STATUS_WAKE_KILL'):
            self.PROC_STATUSES_RAW[psutil.STATUS_WAKE_KILL] = "WK"

        if hasattr(psutil, 'STATUS_SUSPENDED'):
            self.PROC_STATUSES_RAW[psutil.STATUS_SUSPENDED] = "V"

    def get_logfile(self, logfilename='/dev/null'):
        """
        returns the contents of a logfile as a single string with \n chars
        """
        # TODO: write this
        pass

    def get_procinfo(self):
        retval = ""
        today_day = datetime.date.today()
        templ = "%-10s %5s %4s %4s %7s %7s %-13s %-5s %5s %7s  %s"
        attrs = ['pid', 'cpu_percent', 'memory_percent', 'name', 'cpu_times',
                 'create_time', 'memory_info', 'status']
        if os.name == 'posix':
            attrs.append('uids')
            attrs.append('terminal')
        print(templ % ("USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY",
                       "STAT", "START", "TIME", "COMMAND"))
        for p in psutil.process_iter():
            try:
                pinfo = p.as_dict(attrs, ad_value='')
            except psutil.NoSuchProcess:
                pass
            else:
                if pinfo['create_time']:
                    ctime = datetime.datetime.fromtimestamp(
                        pinfo['create_time'])
                    if ctime.date() == today_day:
                        ctime = ctime.strftime("%H:%M")
                    else:
                        ctime = ctime.strftime("%b%d")
                else:
                    ctime = ''
                cputime = time.strftime("%M:%S",
                                        time.localtime(sum(pinfo['cpu_times'])))
                try:
                    user = p.username()
                except KeyError:
                    if os.name == 'posix':
                        if pinfo['uids']:
                            user = str(pinfo['uids'].real)
                        else:
                            user = ''
                    else:
                        raise
                except psutil.Error:
                    user = ''
                if os.name == 'nt' and '\\' in user:
                    user = user.split('\\')[1]
                vms = pinfo['memory_info'] and \
                    int(pinfo['memory_info'].vms / 1024) or '?'
                rss = pinfo['memory_info'] and \
                    int(pinfo['memory_info'].rss / 1024) or '?'
                memp = pinfo['memory_percent'] and \
                    round(pinfo['memory_percent'], 1) or '?'
                status = self.PROC_STATUSES_RAW.get(
                    pinfo['status'], pinfo['status'])
                retval = "%s\n%s" % (retval, (templ % (
                    user[:10],
                    pinfo['pid'],
                    pinfo['cpu_percent'],
                    memp,
                    vms,
                    rss,
                    pinfo.get('terminal', '') or '?',
                    status,
                    ctime,
                    cputime,
                    pinfo['name'].strip() or '?')))
        return retval

    def get_cpuinfo(self):
        retval = ""
        cputimes = psutil.cpu_times(percpu=True)
        cpu = 0
        for cpus in cputimes:
            retval = "%s\n %s: user: %s system: %s idle: %s" % (
                retval, cpu, cpus.user, cpus.system, cpus.idle)
            cpu += 1
        return retval

    def get_meminfo(self):
        # get memory info
        retval = ""
        vram = psutil.virtual_memory()
        retval = "total: %s" % (vram.total)
        retval = "%s\navail: %s" % (retval, vram.available)
        retval = "%s\npercent: %s%%" % (retval, vram.percent)
        swap = psutil.swap_memory()
        retval = "%s\ntotal swap: %s" % (retval, getattr(swap, 'total'))
        retval = "%s\nused swap: %s" % (retval, getattr(swap, 'used'))
        retval = "%s\nfree swap: %s" % (retval, getattr(swap, 'free'))
        return retval

    def get_netif(self, iface=None):
        """
        return either all interfaces with statistics, or one interface as specified by iface
        """
        # TODO: allow caller to specify a single iface
        retval = ""
        for nics, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if self.AF_MAP.get(addr.family) == 'IPv4':
                    retval = "%s\n%s: %s mask %s" % (
                        retval, nics, addr.address, addr.netmask)
                    stats = psutil.net_io_counters(pernic=True)[nics]
                    retval = "%s tx: %-16s rx: %-16s txerr: %-8s rxerr: %-8s" % (
                        retval, stats.bytes_sent, stats.bytes_recv, stats.errout, stats.errin)
        return retval

    def get_volumes(self, vol=None):
        """
        shows the currently mounted volumes and their total, used and free space in bytes
        """
        # TODO: add support for more friendly output (e.g. K, M, G, etc.)
        retval = ""
        for vol in self.VOLUMES:
            p = psutil.disk_usage(vol)
            templ = "[%-10s] total:%-16s used:%-16s free:%-16s"
            retval = retval + "\n" + \
                templ % (
                    vol, getattr(p, "total"), getattr(p, "used"), getattr(p, "free"))
        return retval

    def get_routes(self, dest=None, iface=None):
        """
        shows the current routing table for a specific destination network, interface, or all routes
        """
        # TODO: implement dest and iface filters
        retval = ""
        mycmd = "%s -nr" % ('netstat')
        output, errors = get_cmd_output(mycmd).communicate()
        lines = re.split('\n', output)
        for l in lines:
            # todo: use iface as my search criteria
            if re.search('en0', l):
                retval = "%s\n%s" % (retval, l)
        return retval

    def get_netstat(self):
        """
        get list of open sockets, etc.
        """
        # TODO: this is broke as shit... no idea why.
        templ = "%-5s %-30s %-30s %-13s %-6s %s"
        retval = (templ % (
            "Proto", "Local address", "Remote address", "Status", "PID",
            "Program name"))
        proc_names = {}
        try:
            for p in psutil.process_iter():
                try:
                    proc_names[p.pid] = p.name()
                except psutil.Error:
                    pass
            for c in psutil.net_connections(kind='inet'):
                laddr = "%s:%s" % (c.laddr)
                raddr = ""
                if c.raddr:
                    raddr = "%s:%s" % (c.raddr)
                retval = "%s %s" % (retval, templ % (
                    self.PROTO_MAP[(c.family, c.type)],
                    laddr,
                    raddr or self.AD,
                    c.status,
                    c.pid or self.AD,
                    proc_names.get(c.pid, '?')[:15],
                ))
        except psutil.AccessDenied:
            pass
        return retval

    def package(self):
        """
        gather all the member functions outputs, and logs to a single directory, compress it and remove originals, return the name of the temporary file.
        """
        # TODO: write me
        pass

    def _get_vols(self):
        """
        private method to poputlate the self.VOLUMES array with currently mounted volumes
        """
        partitions = psutil.disk_partitions(all=True)
        for part in partitions:
            self.VOLUMES.append(getattr(part, 'mountpoint'))

    def _get_nics(self):
        """
        private method to populate the self.NICS array with configured interfaces
        """
        for nics, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if self.AF_MAP.get(addr.family) == 'IPv4':
                    self.NICS.append(nics)


if __name__ == '__main__':
    diag = DiagInfo()
    print "------------------------------"
    print diag.get_procinfo()
    print "------------------------------"
    print diag.get_cpuinfo()
    print "------------------------------"
    print diag.get_meminfo()
    print "------------------------------"
    print diag.get_netif()
    print "------------------------------"
    print diag.get_volumes()
    print "------------------------------"
    print diag.get_routes()
    print "------------------------------"
    print diag.get_netstat()

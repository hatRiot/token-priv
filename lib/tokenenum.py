from tabulate import tabulate
from argparse import ArgumentParser
import pykd
import sys
import re

""" Token privileges utility script, depends on pykd and tabulate
"""

# SeUnsolicitedInputPrivilege left off as it's obsolete (folded into SeMachineAccountPrivilege)
# SeCreatePagefilePrivilege may be deprecated as well
PRIVILEGE_BITS = {
    "SeCreateTokenPrivilege"          : 0x000000002,
    "SeAssignPrimaryTokenPrivilege"   : 0x000000003,
    "SeLockMemoryPrivilege"           : 0x000000004,
    "SeIncreaseQuotaPrivilege"        : 0x000000005,
    "SeMachineAccountPrivilege"       : 0x000000006,
    "SeTcbPrivilege"                  : 0x000000007,
    "SeSecurityPrivilege"             : 0x000000008,
    "SeTakeOwnershipPrivilege"        : 0x000000009,
    "SeLoadDriverPrivilege"           : 0x00000000a,
    "SeSystemProfilePrivilege"        : 0x00000000b,
    "SeSystemtimePrivilege"           : 0x00000000c,
    "SeProfileSingleProcessPrivilege" : 0x00000000d,
    "SeIncreaseBasePriorityPrivilege" : 0x00000000e,
    "SeCreatePagefilePrivilege"       : 0x00000000f,
    "SeCreatePermanentPrivilege"      : 0x000000010,
    "SeBackupPrivilege"               : 0x000000011,
    "SeRestorePrivilege"              : 0x000000012,
    "SeShutdownPrivilege"             : 0x000000013,
    "SeDebugPrivilege"                : 0x000000014,
    "SeAuditPrivilege"                : 0x000000015,
    "SeSystemEnvironmentPrivilege"    : 0x000000016,
    "SeChangeNotifyPrivilege"         : 0x000000017,
    "SeRemoteShutdownPrivilege"       : 0x000000018,
    "SeUndockPrivilege"               : 0x000000019,
    "SeSyncAgentPrivilege"            : 0x00000001a,
    "SeEnableDelegationPrivilege"     : 0x00000001b,
    "SeManageVolumePrivilege"         : 0x00000001c,
    "SeImpersonatePrivilege"          : 0x00000001d,
    "SeCreateGlobalPrivilege"         : 0x00000001e,
    "SeTrustedCredManAccessPrivilege" : 0x00000001f,
    "SeRelabelPrivilege"              : 0x000000020,
    "SeIncreaseWorkingSetPrivilege"   : 0x000000021,
    "SeTimeZonePrivilege"             : 0x000000022,
    "SeCreateSymbolicLinkPrivilege"   : 0x000000023,
    "SeDelegateSessionUserImpersonatePrivilege" : 0x000000024
}

class Process(object):
    """ Process object
    """

    def __init__(self, pid):
        self.pid = pid
        self.image = None
        self.cid = None
        self.token = None
        self.objaddr = None
        self.peb = None
        self.current_privileges = {}
        
        self.parse()
        self.build_token_privs()

    def parse(self):
        """ Parse out some process information; probably a cleaner way to do this...
        """

        data = pykd.dbgCommand("!process %04x 1" % self.pid).splitlines()
        for entry in data:
            if 'Image' in entry:
                self.image = entry.split(': ')[1]
            elif 'Cid' in entry and not "Searching" in entry:
                r = re.findall("Cid: (.*?) ", entry)
                if len(r) > 0:
                    self.cid = int(r[0], 16)
                else:
                    print '[-] Could not parse process CID!'

                # fetch peb/objaddr while we're here
                r = re.findall("Peb: (.*?) ", entry)
                if len(r) > 0:
                    self.peb = int(r[0], 16)

                r = re.findall("PROCESS (.*?) ", entry)
                if len(r) > 0:
                    self.objaddr = int(r[0], 16)

            elif 'Token' in entry:
                entry = entry.replace(" ","")
                self.token = int(entry.split("Token")[1], 16)

    def build_token_privs(self):
        """ Build a dictionary containing enabled and available privileges
        """

        data = pykd.dbgCommand("!token %08x" % self.token).splitlines()
        start_privs = [i for i, s in enumerate(data) if 'Privs:' in s][0] + 1
        end_privs = [i for i, s in enumerate(data) if 'Authentication ID' in s][0]
        for priv in data[start_privs:end_privs]:
            _priv = priv.split(" ")
            _priv = filter(None, _priv)
            if 'Enabled' in priv:
                self.current_privileges[_priv[2]] = True
            else:
                self.current_privileges[_priv[2]] = False

    def enable_privilege(self, privilege):
        """ Enable a specific privilege on the process token
        """

        if not privilege in PRIVILEGE_BITS.keys():
            return False

        # read, modify, and set the bit
        default = pykd.ptrSignQWord(self.token + 0x40)
        enabled = pykd.ptrSignQWord(self.token + 0x48)
        enabled |= 1 << PRIVILEGE_BITS[privilege]
        default |= 1 << PRIVILEGE_BITS[privilege]
        pykd.writeSignQWords(self.token + 0x48, [enabled])
        pykd.writeSignQWords(self.token + 0x40, [default])
        return True

    def disable_privilege(self, privilege):
        """ Disable a specific privilege
        """

        if not privilege in PRIVILEGE_BITS.keys():
            return False

        # read, modify, and set the bit
        default = pykd.ptrSignQWord(self.token + 0x40)
        enabled = pykd.ptrSignQWord(self.token + 0x48)
        enabled &= ~(1 << PRIVILEGE_BITS[privilege])
        default &= ~(1 << PRIVILEGE_BITS[privilege])
        pykd.writeSignQWords(self.token + 0x40, [default])
        pykd.writeSignQWords(self.token + 0x48, [enabled])
        return True

def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-e', help='Enable privilege', dest='enable', nargs='*', default=None)
    parser.add_argument('-d', help='Disable privilege', dest='disable', nargs='*', default=None)
    parser.add_argument('-p', help='Process ID', dest='pid', required=True, type=int)
    opts = parser.parse_args(sys.argv[1:])
    return opts

def run(opts):
    print '[+] Finding target pid %d...' % opts.pid
    process = Process(opts.pid)

    print '[+] Current privileges:'
    print '\n%s\n' % tabulate({"Privilege" : process.current_privileges.keys(),
                                "State" : process.current_privileges.values()},
                              headers="keys")

    if opts.enable:
        for priv in opts.enable:
            if process.enable_privilege(priv):
                print '[+] %s enabled' % priv
            else:
                print '[-] Could not enable %s' % priv

    if opts.disable:
        for priv in opts.disable:
            if process.disable_privilege(priv):
                print '[+] %s disabled' % priv
            else:
                print '[-] Could not disable %s' % priv

if __name__ == "__main__":
    if not pykd.isKernelDebugging():
        print 'Currently not kd!'

    run(parse_args())
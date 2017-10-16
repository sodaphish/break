import sys

try:
    import ipaddress
    import subprocess32
    import psutil

except Exception as e:
    print "unmet dependencies required for splib -- %s" % (e)
    print "splib requires the following packages:"
    print "\tMySQLdb"
    print "\tbs4"
    print "\tipaddress"
    print "\tsubprocess32"
    print "these can be installed via `pip install <package>`"
    sys.exit(2)

import sys

try:
    from sp.base import Logging
except Exception as e:
    print "couldn't load splib"
    sys.exit(1)

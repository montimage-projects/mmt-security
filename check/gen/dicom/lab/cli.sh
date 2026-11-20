#!/bin/sh
# Client side of the lab (10.77.0.20): DCMTK or pynetdicom sessions against the SCP.
# The C-STOREs seed the SCP, whose store is in memory.
ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1
cd /tmp; for i in 1 2 3; do dump2dcm /lab/img$i.dump img$i.dcm 2>/dev/null; done
if [ "$1" = dcmtk ]; then sh /lab/cli_dcmtk.sh; else python3 /lab/cli_pnd.py; fi

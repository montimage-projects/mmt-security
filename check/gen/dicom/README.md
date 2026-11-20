# DICOM check captures

Captures for the DICOM rules 200-228 (`check/pcap/dicom_*` and
`check/pcap/220.dicom_association_flood.pcap`).

1. Benign sessions, recorded in a lab: a pynetdicom 2.1.1 Query/Retrieve SCP
   (`lab/scp.py`, AE `LABPACS`) and either DCMTK 3.6.7 clients
   (`lab/cli_dcmtk.sh`: echoscu, storescu, six wildcard findscu, a cancelled
   findscu, movescu, echoscu, all with default options except `-aet LABSCU`)
   or pynetdicom clients (`lab/cli_pnd.py`, the same sequence).

       lab/lab.sh benign_dcmtk dcmtk
       lab/lab.sh benign_pnd pnd

2. Attacks, one TCP connection each, crafted with scapy, and the merge:

       python3 dicom_pcaps.py attacks attacks.pcap
       python3 dicom_pcaps.py merge lab/cap/benign_dcmtk.pcap attacks.pcap ../../pcap/dicom_dcmtk_benign_attacks.pcap
       python3 dicom_pcaps.py merge lab/cap/benign_pnd.pcap attacks.pcap ../../pcap/dicom_pynetdicom_benign_attacks.pcap
       python3 dicom_pcaps.py flood ../../pcap/220.dicom_association_flood.pcap

The expected files list only the alerts of the DICOM rules each capture tests
(200, 201, 202, 208, 209, 213, 216, 219, 220, 221, 223, 224, 226, 227, 228), so
`make check` also fails when one of them alerts on the benign sessions. The
benign sessions still raise alerts of other DICOM rules (206, 212), which the
expected files leave out.

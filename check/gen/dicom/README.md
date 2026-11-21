# DICOM check captures

Captures for the DICOM rules 200-228 (`check/pcap/dicom_*` and
`check/pcap/220.dicom_association_flood.pcap`), and the embedded C that several
of these rules share (`blocks/`).

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
`make check` also fails when one of them alerts on the benign sessions. Rules
206 and 212, which alerted on these benign sessions, are disabled: they are in
`rules/properties_all` only (fork issue #27).

3. The PDU boundary tracker and the rate rules, crafted with scapy (fork PR #15
   follow-up):

       python3 dicom_pcaps.py segmenting-benign ../../pcap/dicom_segmenting_benign.pcap
       python3 dicom_pcaps.py segmenting-attacks ../../pcap/dicom_segmenting_attacks.pcap
       python3 dicom_pcaps.py tracker-edges ../../pcap/dicom_tracker_edges.pcap
       python3 dicom_pcaps.py parallel-associations ../../pcap/dicom_parallel_associations.pcap
       python3 dicom_pcaps.py rates ../../pcap/dicom_rate_windows.pcap
       python3 dicom_pcaps.py parallel-sources ../../pcap/dicom_parallel_sources.pcap

   - `dicom_segmenting_benign`: C-STOREs segmented as pynetdicom (one write per
     PDU, cut every 1448 bytes) and as DCMTK (the 12-byte PDU and PDV header in a
     segment of its own) do, with PDU headers split across segments (3 + 3, 1 + 5,
     5 + 1, 4 + 8), pixel data that reads as the PDU headers each rule flags at
     segment starts, a segment lost inside a PDU body, a segment holding a header
     lost, and a 20 MiB P-DATA-TF with a whole A-ASSOCIATE-RQ in its data. Its
     expected file is empty: no rule of the batch may alert.
   - `dicom_segmenting_attacks`: attacks after such data in the same connection
     (200, 208, 226, 216 6 s after the data), a header of the attack PDU split
     1 + 5, a retransmitted attack (one alert), 12 parallel associations from
     one client to one SCP port, each ending with a PDU of type 9 (12 alerts of
     200), a segment far from the stream (100 MiB ahead, 16 MiB + 1 behind) that
     must not blind the direction or make 216 forget the data (200, 216, 200),
     a P-DATA-TF sent only by the SCP before the client's A-ASSOCIATE-RQ
     (216), and a far segment with the fixed fields of an A-ASSOCIATE-RQ but no
     Application Context Item, ignored too (200).
   - `dicom_tracker_edges`: reuses of a 4-tuple: a TIME_WAIT reuse (new initial
     sequence number = old + 65537) after a release and after an A-ABORT,
     random initial sequence numbers after a release and after a TCP reset, one
     64 KiB beyond `PDU_TRACK_NEAR` after a reset; a capture loss of 64 KiB less than
     `PDU_TRACK_NEAR` at a PDU header, then data that starts like a whole
     A-ASSOCIATE-RQ; data that starts with the fixed fields of an
     A-ASSOCIATE-RQ but no Application Context Item, after a lost header and as
     the first segment of a capture that starts mid-connection. Its expected
     file is empty: no rule of the batch may alert.
   - `dicom_parallel_associations`: 128 associations from one client to one SCP
     port open at once, each ending with a PDU of type 9 (128 alerts of 200).
   - `dicom_rate_windows`: 223 with 12 wildcard queries over 30 s (no alert) and
     10 in 1 s (one); 220 with two sources of 15 A-ASSOCIATE-RQ each in 4 s (no
     alert) and one of 22 in 2 s (two); 228 with 12 sources of one /16 (12).
   - `dicom_parallel_sources`: 220 and 223 with 10 sources of one /16 at once,
     each over the threshold (10 alerts of each).

   These six run with `check/pcap/<name>.opt`, which excludes every rule but
   200, 201, 202, 208, 209, 213, 216, 219, 220, 221, 223, 224, 226, 227 and 228,
   so their expected files list every alert of these rules.

## Shared embedded C

`blocks/pdu_track.c` (the PDU boundary tracker of rules 200, 208, 209, 216, 219,
220, 221, 224, 226, 227 and 228) and `blocks/dimse_walk.c` (the DIMSE command set
walker of rules 201, 202 and 213) are copied verbatim into those rules and their
`rules/properties_all/` mirrors. Edit the block, then

    check/dicom-blocks.sh --write

`make check` runs `check/dicom-blocks.sh`, which fails when a copy differs from
its block, when a mirror differs from its rule, or when the embedded C of one of
these rules (or of 223) does not compile on its own.

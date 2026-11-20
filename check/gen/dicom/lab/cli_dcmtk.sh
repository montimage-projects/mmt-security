#!/bin/sh
H=10.77.0.10; P=11112
/usr/bin/echoscu -aet LABSCU $H $P
/usr/bin/storescu -aet LABSCU $H $P /tmp/img1.dcm /tmp/img2.dcm /tmp/img3.dcm
for pn in 'D*' 'A*' 'S*' 'M*' 'J*' '*'; do
  /usr/bin/findscu -aet LABSCU -P -k QueryRetrieveLevel=PATIENT -k "PatientName=$pn" -k PatientID $H $P
done
/usr/bin/findscu -aet LABSCU --cancel 1 -P -k QueryRetrieveLevel=PATIENT -k 'PatientName=*' -k PatientID $H $P
/usr/bin/movescu -aet LABSCU -aem LABSCU --port 11113 -od /tmp -S -k QueryRetrieveLevel=STUDY -k StudyInstanceUID=1.2.826.0.1.3680043.2.1125.2.1 $H $P
/usr/bin/echoscu -aet LABSCU $H $P

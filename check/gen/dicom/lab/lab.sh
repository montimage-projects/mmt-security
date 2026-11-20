#!/bin/sh
# usage: lab.sh <capture name> <dcmtk|pnd>
# Runs the pynetdicom 2.1.1 SCP (AE LABPACS, 10.77.0.10:11112) and one client set,
# and writes cap/<capture name>.pcap. Offloads are off, so the capture holds real
# 1500-byte-MTU segments.
set -e
S=$(dirname "$(readlink -f "$0")"); mkdir -p "$S/cap"
docker build -q -t secfork-dicom-lab "$S" >/dev/null
docker network inspect secfork-dicomlab >/dev/null 2>&1 || docker network create --subnet 10.77.0.0/24 secfork-dicomlab >/dev/null
docker rm -f secfork-dicom-scp >/dev/null 2>&1 || true
docker run -d --name secfork-dicom-scp --network secfork-dicomlab --ip 10.77.0.10 --cap-add NET_ADMIN --cap-add NET_RAW -v "$S:/lab:ro" -v "$S/cap:/cap" secfork-dicom-lab /lab/scp.sh "$1" >/dev/null
sleep 4
docker run --rm --network secfork-dicomlab --ip 10.77.0.20 --cap-add NET_ADMIN -v "$S:/lab:ro" secfork-dicom-lab /lab/cli.sh "$2" > "$S/cap/$1.cli.log" 2>&1
sleep 2
docker exec secfork-dicom-scp sh -c "kill -INT \$(pidof tcpdump); sleep 1; chown $(id -u):$(id -g) /cap/*"
docker rm -f secfork-dicom-scp >/dev/null

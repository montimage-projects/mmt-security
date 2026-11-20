FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-venv dcmtk tcpdump ethtool ca-certificates \
 && rm -rf /var/lib/apt/lists/* && python3 -m venv /venv && /venv/bin/pip install -q pynetdicom==2.1.1 pydicom==2.4.4
ENV PATH=/venv/bin:$PATH

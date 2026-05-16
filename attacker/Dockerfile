FROM kalilinux/kali-rolling:latest

# Install networking attack tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-scapy \
    bettercap \
    tshark \
    net-tools \
    iputils-ping \
    iproute2 \
    arp-scan \
    dsniff \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --break-system-packages -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Enable IP forwarding at container start
RUN echo '#!/bin/bash\necho 1 > /proc/sys/net/ipv4/ip_forward\nexec "$@"' > /entrypoint.sh \
    && chmod +x /entrypoint.sh

WORKDIR /opt/attack-scripts

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]

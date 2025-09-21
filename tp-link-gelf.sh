#!/bin/bash
# Proxmox LXC install script for tp-link-graylog-forwarder.pl

# --- CONFIGURATION ---
CTID=113
HOSTNAME="tplink-to-gelf"      # Change to desired hostname
MEMORY=256                     # RAM in MB
DISK=2                         # Disk size in GB
TEMPLATE="local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst" # Adjust to your template
GRAYLOG_IP="192.168.10.11"     # Set your Graylog IP here
GRAYLOG_PORT="12201"           # Set your Graylog GELF port here

# --- CREATE CONTAINER ---
pct create $CTID $TEMPLATE \
    --hostname $HOSTNAME \
    --memory $MEMORY \
    --cores 1 \
    --net0 name=eth0,bridge=vmbr0,ip=dhcp \
    --rootfs local-lvm:$DISK \
    --features nesting=1 \
    --unprivileged 1 \
    --ostype debian \
    --description "TP-Link syslog to Graylog GELF forwarder"

pct start $CTID

# --- INSTALL DEPENDENCIES ---
pct exec $CTID -- apt-get update
pct exec $CTID -- apt-get install -y --no-install-recommends \
    wget perl libdata-printer-perl libtry-tiny-perl libio-compress-perl libjson-xs-perl libreadonly-perl

# --- COPY SCRIPT ---
# Copy the Perl script from Proxmox host to container
pct exec $CTID -- mkdir -p /opt/lib/TPLinkSyslogMessage
pct exec $CTID -- wget -O /opt/tp-link-graylog-forwarder.pl https://raw.githubusercontent.com/Leeft/TP-Link-to-GELF/refs/heads/main/bin/tp-link-graylog-forwarder.pl
pct exec $CTID -- wget -O /opt/lib/TPLinkSyslogMessage/Parser.pm https://raw.githubusercontent.com/Leeft/TP-Link-to-GELF/refs/heads/main/lib/TPLinkSyslogMessage/Parser.pl

# --- SET ENVIRONMENT VARIABLES ---
pct set $CTID -env GRAYLOG_IP=$GRAYLOG_IP
pct set $CTID -env GRAYLOG_PORT=$GRAYLOG_PORT

# --- OPTIONAL: SET AUTOSTART ---
pct set $CTID -onboot 1

# --- CREATE SYSTEMD SERVICE ---
pct exec $CTID -- bash -c 'cat > /etc/systemd/system/tplink-gelf.service <<EOF
[Unit]
Description=TP-Link syslog to Graylog GELF forwarder
After=network.target

[Service]
Type=simple
Environment=GRAYLOG_IP='$GRAYLOG_IP'
Environment=GRAYLOG_PORT='$GRAYLOG_PORT'
ExecStart=/usr/bin/perl /opt/tp-link-graylog-forwarder.pl
Restart=always

[Install]
WantedBy=multi-user.target
EOF'

pct exec $CTID -- systemctl daemon-reload
pct exec $CTID -- systemctl enable tplink-gelf
pct exec $CTID -- systemctl start tplink-gelf

echo "Container $CTID setup complete. Script running as a service."
#!/bin/bash

cpath=$(pwd)

cat > /etc/systemd/system/pythapi.service <<EOM
[Unit]
Description=PythAPI Server
After=network.target

[Service]
User=root
ExecStart=$cpath/pythapi.py --no-fancy

[Install]
WantedBy=multi-user.target
EOM

systemctl daemon-reload

#!/bin/bash

sudo ufw allow 1435/tcp
sudo ufw reload

sudo /opt/mssql/bin/mssql-conf set network.tcpport 1435
sudo /opt/mssql/bin/mssql-conf set network.ipaddress 0.0.0.0
sudo systemctl restart mssql-server

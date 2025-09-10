#!/bin/bash -e
################################################################################
##  File:  install-apache.sh
##  Desc:  Install Apache HTTP Server
################################################################################

if ! systemctl is-system-running; then
    exit 0
fi

# Install Apache
apt-get install apache2

# Disable apache2.service
systemctl is-active --quiet apache2.service && systemctl stop apache2.service
systemctl disable apache2.service

invoke_tests "WebServers" "Apache"

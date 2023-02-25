#!/bin/bash

rm -f /home/rcoscali/Public/MAC_Prov_Extract/var/lib/*
rm -f /home/rcoscali/Public/MAC_Prov_Extract/var/log/*
touch /home/rcoscali/Public/MAC_Prov_Extract/var/lib/keystore.db
node /home/rcoscali/Public/MAC_Prov_Extract/bin/keystore --init-db

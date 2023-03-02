#!/bin/bash

if ! test -z "$MAC_PROV_ROOT"; then
  mkdir -p var/{lib,log}
  rm -f $MAC_PROV_ROOT/var/lib/*
  rm -f $MAC_PROV_ROOT/var/log/*
  touch $MAC_PROV_ROOT/var/lib/keystore.db
  node $MAC_PROV_ROOT/bin/keystore --init-db
else
  echo MAC_PROV_ROOT not defined
fi

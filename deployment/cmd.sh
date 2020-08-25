#!/bin/sh
cp evioPlugin /opt/cni/bin
mv /opt/cni/bin/host-local /opt/cni/bin/bkp-host-local
cp host-local /opt/cni/bin
./evioUtilities

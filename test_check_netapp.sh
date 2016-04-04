#!/bin/bash

FILER=$1

./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --aggregatebytes
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --aggregateinodes
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --autosupport
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --cfinterconnect
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --cfpartner
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --diskhealth
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --enclosurefanhealth
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --enclosurepsuhealth
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --fanhealth
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --globalstatus
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --nvrambattery
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --overtemperature
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --psuhealth
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --treebytequotas
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --treefilequotas
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --uptime
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --userbytequotas
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --userfilequotas
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --volumebytes
./check_netapp.pl --hostname ${FILER} --warning 70 --critical 90 --volumeinodes
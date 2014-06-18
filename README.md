check_netapp
============

A nagios plugin for Netapp filers, written in Perl.


    martin@molly:~/check_netapp$ ./check_netapp.pl
    Mandatory parameter 'hostname' missing in call to (eval)
    
    check_netapp.pl (ver. 2014061600) [-Cchw] [long options...]
            Plugin parameters:
            -h --hostname        NetApp hostname or IP.
            -C --community       SNMP community string.
            --help               Print help and usage.
                               
            Nagios parameters:
            -w --warning         Sets the warning threshold for the check.
            -c --critical        Sets the critical threshold for the check.
                               
            Available Metrics:
            --aggregatebytes     Check aggregate byte usage.
            --aggregateinodes    Check aggregate inode usage.
            --autosupport        Check autosupport status.
            --cfpartnerstatus    Check clustered failover partner status.
            --diskhealth         Check physical disk health.
            --fanhealth          Check fan health.
            --globalstatus       Check global system status.
            --nvrambattery       Check NVRAM battery status.
            --overtemperature    Check environment over temperature status.
            --psuhealth          Check PSU health.
            --treefilequotas     Check tree file quotas.
            --treebytequotas     Check tree byte quotas.
            --uptime             Check system uptime.
            --userfilequotas     Check user file quotas.
            --userbytequotas     Check user byte quotas.
            --volumebytes        Check volume byte usage.
            --volumeinodes       Check volume inode usage.
                               
            Example usage:
            ./check_netapp.pl --hostname 1.2.3.4 --warning 70 --critical 90 --aggregatebytes
            ./check_netapp.pl -h 1.2.3.4 -w 70 -c 90 --aggregatebytes

Credits
=======

Thanks to Hitachi Data Systems (UK) Ltd, for allowing me to open this plugin up
to the community.  Any errors or ommissions are entirely the fault of the
author.

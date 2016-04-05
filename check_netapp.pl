#!/usr/bin/perl

use strict;
use warnings;

use Cwd 'abs_path';
use File::Basename;
use Getopt::Long::Descriptive;
use Monitoring::Plugin;
use Monitoring::Plugin qw(%STATUS_TEXT);
use Net::SNMP;
use Number::Bytes::Human qw(format_bytes parse_bytes);
use Time::Duration;
use Time::Duration::Parse;
use YAML::XS qw(DumpFile LoadFile);

my $VERSION = '2016040400';

my ( $opt, $usage ) = describe_options(
    "%c (ver. $VERSION) %o",
    ['Plugin parameters:'],
    [ 'hostname|h=s'  => 'NetApp hostname or IP.', { required => 1 } ],
    [ 'community|C=s' => 'SNMP community string.', { required => 1, default => 'public' } ],
    [ 'help' => 'Print help and usage.' ],
    [],
    ['Nagios parameters:'],
    [ 'warning|w=s'  => 'Sets the warning threshold for the check.' ],
    [ 'critical|c=s' => 'Sets the critical threshold for the check.' ],
    [],
    ['Available Metrics:'],
    [
        'metric|m=s' => hidden => {
            one_of => [
                [ 'aggregatebytes'     => 'Check aggregate byte usage.' ],
                [ 'aggregateinodes'    => 'Check aggregate inode usage.' ],
                [ 'autosupport'        => 'Check autosupport status.' ],
                [ 'cfinterconnect'     => 'Check clustered failover interconnect status.' ],
                [ 'cfpartner'          => 'Check clustered failover partner status.' ],
                [ 'diskhealth'         => 'Check physical disk health.' ],
                [ 'enclosurefanhealth' => 'Check enclosure fan health.' ],
                [ 'enclosurepsuhealth' => 'Check enclosure PSU health.' ],
                [ 'fanhealth'          => 'Check fan health.' ],
                [ 'globalstatus'       => 'Check global system status.' ],
                [ 'nvrambattery'       => 'Check NVRAM battery status.' ],
                [ 'overtemperature'    => 'Check environment over temperature status.' ],
                [ 'psuhealth'          => 'Check PSU health.' ],
                [ 'snapshotcount'      => 'Check volume snapshot count.' ],
                [ 'treebytequotas'     => 'Check tree byte quotas.' ],
                [ 'treefilequotas'     => 'Check tree file quotas.' ],
                [ 'uptime'             => 'Check system uptime.' ],
                [ 'userbytequotas'     => 'Check user byte quotas.' ],
                [ 'userfilequotas'     => 'Check user file quotas.' ],
                [ 'volumebytes'        => 'Check volume byte usage.' ],
                [ 'volumeinodes'       => 'Check volume inode usage.' ],
            ]
        }
    ],
    [],
    ['Example usage:'],
    ["$0 --hostname 1.2.3.4 --warning 70 --critical 90 --aggregatebytes"],
    ["$0 -h 1.2.3.4 -w 70 -c 90 --aggregatebytes"],
    [],
);

my $community = $opt->community;
my $critical  = $opt->critical;
my $hostname  = $opt->hostname;
my $metric    = $opt->metric || '';
my $warning   = $opt->warning;

if ( $opt->help || $metric eq '' ) {
    print $usage->text;
    exit;
}

my $config = dirname( abs_path($0) ) . "/check_netapp_config.yaml";
my $yaml;
if ( -e "$config" ) {
    $yaml = LoadFile("$config");
}

$hostname = lc($hostname);
if ( $yaml->{hostmap}->{$hostname} ) {
    $hostname = lc( $yaml->{hostmap}->{$hostname} );
}

my $plugin  = Monitoring::Plugin->new;
my $baseOID = '1.3.6.1.4.1.789';

my ( $session, $error ) = Net::SNMP->session(
    -hostname  => "$hostname",
    -community => "$community",
    -timeout   => 30,
    -version   => 'snmpv2c'
);
$plugin->nagios_exit( UNKNOWN, "Could not create SNMP session to $hostname" ) unless $session;

my ( $warnneeded, $critneeded ) = ( 0, 0 );
my @warncrit = qw(aggregatebytes aggregateinodes treebytequotas treefilequotas uptime userbytequotas userfilequotas volumebytes volumebytes);
if ( grep /^$metric$/, @warncrit ) {
    $warnneeded = 1;
    $critneeded = 1;
}

if ( $warnneeded && !defined($warning) ) {
    $plugin->nagios_exit( UNKNOWN, "The $metric check requires a warning threshold." );
}

if ( $critneeded && !defined($critical) ) {
    $plugin->nagios_exit( UNKNOWN, "The $metric check requires a critical threshold." );
}

my $dispatch = {
    aggregatebytes     => \&checkAggregateBytes,
    aggregateinodes    => \&checkAggregateInodes,
    autosupport        => \&checkAutosupport,
    cfinterconnect     => \&checkCFInterconnect,
    cfpartner          => \&checkCFPartner,
    diskhealth         => \&checkDiskHealth,
    enclosurefanhealth => \&checkEncFanHealth,
    enclosurepsuhealth => \&checkEncPSUHealth,
    fanhealth          => \&checkFanHealth,
    globalstatus       => \&checkGlobalStatus,
    nvrambattery       => \&checkNVRAMBattery,
    overtemperature    => \&checkOverTemperature,
    psuhealth          => \&checkPSUHealth,
    snapshotcount      => \&checkSnapshotCount,
    treebytequotas     => \&checkTreeByteQuotas,
    treefilequotas     => \&checkTreeFileQuotas,
    uptime             => \&checkUptime,
    userbytequotas     => \&checkUserByteQuotas,
    userfilequotas     => \&checkUserFileQuotas,
    volumebytes        => \&checkVolumeBytes,
    volumeinodes       => \&checkVolumeInodes,
};

if ( exists $dispatch->{$metric} ) {
    $dispatch->{$metric}->();
} else {
    $plugin->add_message( CRITICAL, "No handler found for metric $metric." );
}

my ( $exitcode, $message ) = $plugin->check_messages;
$plugin->nagios_exit( $exitcode, $message );

sub checkAggregateBytes {
    my %dfinfo = getDiskSpaceInfo();
    my ( $errorcount, $aggcount ) = ( 0, 0 );
    foreach my $this ( keys %dfinfo ) {
        next if ( $dfinfo{$this}{isAggregate} == 0 || $dfinfo{$this}{isSnapshot} == 1 );
        my $usedbytes = $dfinfo{$this}{PcentUsedBytes};
        my $hused     = $dfinfo{$this}{HumanUsedBytes};
        my $htotal    = $dfinfo{$this}{HumanTotalBytes};
        my $name      = $dfinfo{$this}{Name};
        $aggcount++;
        $exitcode = $plugin->check_threshold( check => $usedbytes, warning => $warning, critical => $critical );
        if ( $exitcode != OK ) {
            $plugin->add_message( $exitcode, "Aggregate \'$name\': $hused/$htotal ($usedbytes%)." );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        my $message = "$aggcount aggregate";
        $message .= $aggcount == 1 ? ' is OK' : 's are OK';
        $message .= '.';
        $plugin->add_message( OK, $message );
    }
}

sub checkAggregateInodes {
    my %dfinfo = getDiskSpaceInfo();
    my ( $errorcount, $aggcount ) = ( 0, 0 );
    foreach my $this ( keys %dfinfo ) {
        next if ( $dfinfo{$this}{isAggregate} == 0 || $dfinfo{$this}{isSnapshot} == 1 );
        my $usedinodes = $dfinfo{$this}{PcentUsedInodes};
        my $used       = $dfinfo{$this}{UsedInodes};
        my $total      = $dfinfo{$this}{TotalInodes};
        my $name       = $dfinfo{$this}{Name};
        $aggcount++;
        $exitcode = $plugin->check_threshold( check => $usedinodes, warning => $warning, critical => $critical );
        if ( $exitcode != OK ) {
            $plugin->add_message( $exitcode, "Aggregate \'$name\': $used/$total ($usedinodes%)." );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        my $message = "$aggcount aggregate";
        $message .= $aggcount == 1 ? ' is OK' : 's are OK';
        $message .= '.';
        $plugin->add_message( OK, $message );
    }
}

sub checkAutosupport {
    my $message = 'Autosupport status is okay.';
    my $state   = snmpGetRequest( "$baseOID.1.2.7.1.0", "autosupport status", 0 );
    my $success = snmpGetRequest( "$baseOID.1.2.7.3.0", "autosupport successful sends", 0 );
    my $failed  = snmpGetRequest( "$baseOID.1.2.7.4.0", "autosupport failed sends", 0 );
    my $total   = $success + $failed;
    if ( $state != 1 ) {
        $message = snmpGetRequest( "$baseOID.1.2.7.2.0", "autosupport status message", 0 );
        $message =~ s/\n+/ /g;
    }
    my $exitcode = $state == 1 ? OK : CRITICAL;
    $message .= " $success/$total successful autosupport sends.";
    $plugin->add_message( $exitcode, $message );
}

sub checkCFInterconnect {
    my %cfinfo  = getClusteredFailoverInfo();
    my $state   = $cfinfo{InterconnectStatus};
    my $message = 'Interconnect is ';
    if ( $state == 1 ) { $message .= 'not present.';      $exitcode = OK; }
    if ( $state == 2 ) { $message .= 'down.';             $exitcode = CRITICAL; }
    if ( $state == 3 ) { $message .= 'partially failed.'; $exitcode = WARNING; }
    if ( $state == 4 ) { $message .= 'up.';               $exitcode = OK; }
    $plugin->add_message( $exitcode, $message );
}

sub checkCFPartner {
    my %cfinfo = getClusteredFailoverInfo();
    if ( $cfinfo{Settings} == 1 ) {
        $plugin->add_message( OK, 'Clustered failover not configured.' );
        return;
    }
    my $name    = $cfinfo{PartnerName} || '';
    my $state   = $cfinfo{State};
    my $message = "Clustered failover partner ";
    if ( $name ne '' ) { $message .= "($name) "; }
    if ( $state == 1 ) { $message .= 'may be down.';         $exitcode = WARNING; }
    if ( $state == 2 ) { $message .= 'is okay.';             $exitcode = OK; }
    if ( $state == 3 ) { $message .= 'is dead.';             $exitcode = CRITICAL; }
    if ( $state == 4 ) { $message .= 'has been taken over.'; $exitcode = WARNING; }
    $plugin->add_message( $exitcode, $message );
}

sub checkDiskHealth {
    my ( $exitcode, $message );
    my $errorcount = 0;
    my %dhinfo     = getDiskHealthInfo();

    if ( $dhinfo{Failed} > 0 ) {
        $errorcount++;
        $plugin->add_message( CRITICAL, $dhinfo{Failed} . " failed disks: $dhinfo{FailedMessage}" );
    }

    if ( $dhinfo{Reconstructing} > 0 ) {
        $errorcount++;
        $plugin->add_message( WARNING, $dhinfo{Reconstructing} . ' disk(s) reconstructing.' );
    }

    if ( $dhinfo{ReconstructingParity} > 0 ) {
        $errorcount++;
        $plugin->add_message( WARNING, $dhinfo{ReconstructingParity} . ' disk(s) parity reconstructing.' );
    }

    if ( $dhinfo{AddingSpare} > 0 ) {
        $errorcount++;
        $plugin->add_message( WARNING, $dhinfo{AddingSpare} . ' spare disk(s) being added.' );
    }

    if ( $errorcount == 0 ) {
        $plugin->add_message( OK, "$dhinfo{Total} disks present, $dhinfo{Active} active." );
    }
}

sub checkEncFanHealth {
    my $enccount = enclosuresPresent();
    return if $enccount == 0;
    my %encinfo = getEnclosureInfo();
    my ( $errorcount, $totpresent ) = ( 0, 0 );
    foreach my $this ( keys %encinfo ) {
        my $present = $encinfo{$this}{FansPresentCount};
        my $failed  = $encinfo{$this}{FansFailedCount};
        $totpresent += $present;
        if ( $failed != 0 ) {
            my $message = "Enclosure $this has $failed failed fan";
            $message .= $failed != 1 ? 's' : '';
            $message .= '.';
            $plugin->add_message( CRITICAL, $message );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        $plugin->add_message( OK, "$enccount enclosures, $totpresent fans present and OK." );
    }

}

sub checkEncPSUHealth {
    my $enccount = enclosuresPresent();
    return if $enccount == 0;
    my %encinfo = getEnclosureInfo();
    my ( $errorcount, $totpresent ) = ( 0, 0 );
    foreach my $this ( keys %encinfo ) {
        my $present = $encinfo{$this}{PowerSuppliesPresentCount};
        my $failed  = $encinfo{$this}{PowerSuppliesFailedCount};
        $totpresent += $present;
        if ( $failed != 0 ) {
            my $message = "Enclosure $this has $failed failed power suppl";
            $message .= $failed == 1 ? 'y' : 'ies';
            $message .= '.';
            $plugin->add_message( CRITICAL, $message );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        $plugin->add_message( OK, "$enccount enclosures, $totpresent PSUs present and OK." );
    }

}

sub checkFanHealth {
    my %einfo = getEnvironmentInfo();
    my ( $exitcode, $message ) = ( $exitcode = $einfo{FailedFanCount} == 0 ? OK : CRITICAL, $einfo{FailedFanMessage} );
    $plugin->add_message( $exitcode, $message );
}

sub checkGlobalStatus {
    my $message = 'Global status is okay.';
    my $state = snmpGetRequest( "$baseOID.1.2.2.4.0", "global status", 0 );
    if ( $state != 3 ) {
        $message = snmpGetRequest( "$baseOID.1.2.2.25.0", "global status message", 0 );
        $message =~ s/\n+/ /g;
    }
    my $exitcode = $state == 3 ? OK : CRITICAL;
    $plugin->add_message( $exitcode, $message );
}

sub checkNVRAMBattery {
    my $exitcode;
    my $state = snmpGetRequest( "$baseOID.1.2.5.1.0", "NVRAM battery status", 0 );
    my $message = 'NVRAM battery is ';
    if ( $state == 1 ) { $message .= 'OK';                   $exitcode = OK; }
    if ( $state == 2 ) { $message .= 'partially discharged'; $exitcode = WARNING; }
    if ( $state == 3 ) { $message .= 'full discharged';      $exitcode = CRITICAL; }
    if ( $state == 4 ) { $message .= 'not present';          $exitcode = WARNING; }
    if ( $state == 5 ) { $message .= 'near end of life';     $exitcode = WARNING; }
    if ( $state == 6 ) { $message .= 'at end of life';       $exitcode = CRITICAL; }
    if ( $state == 7 ) { $message .= 'unknown';              $exitcode = WARNING; }
    if ( $state == 8 ) { $message .= 'overcharged';          $exitcode = WARNING; }
    if ( $state == 9 ) { $message .= 'fully charged';        $exitcode = WARNING; }
    $message .= '.';
    $plugin->add_message( $exitcode, $message );
}

sub checkOverTemperature {
    my %einfo    = getEnvironmentInfo();
    my $exitcode = $einfo{OverTemperature} == 1 ? OK : CRITICAL;
    my $message  = 'Environment is ';
    if ( $exitcode == OK ) {
        $message .= 'within ';
    } else {
        $message .= 'outside ';
    }
    $message .= 'temperature limits.';
    $plugin->add_message( $exitcode, $message );
}

sub checkPSUHealth {
    my %einfo = getEnvironmentInfo();
    my ( $exitcode, $message ) = ( $exitcode = $einfo{FailedPSUCount} == 0 ? OK : CRITICAL, $einfo{FailedPSUMessage} );
    $plugin->add_message( $exitcode, $message );
}

sub checkSnapshotCount {
    my %snapshotinfo  = getSnapshotInfo();
    my %snapshotcount = ();
    foreach my $idx ( keys %snapshotinfo ) {
        my $volumename = $snapshotinfo{$idx}{VolumeName};
        $snapshotcount{$volumename}++;
    }
    foreach my $idx ( sort keys %snapshotcount ) {
        my $count   = $snapshotcount{$idx};
        my $message = "$idx has $count snapshot";
        $message .= $count != 1 ? 's.' : '.';
        my $exitcode = $plugin->check_threshold( check => $count, warning => $warning, critical => $critical );
        $plugin->add_message( $exitcode, $message );
    }
}

sub checkTreeByteQuotas {
    my %qinfo = getQuotaInfo();
    my ( $errorcount, $qcount, $qunlim ) = ( 0, 0, 0 );
    foreach my $this ( keys %qinfo ) {
        next if $qinfo{$this}{Type} != 3;
        if ( $qinfo{$this}{BytesUnlimited} == 2 ) {
            $qunlim++;
            next;
        }
        my $tree      = $qinfo{$this}{QTree};
        my $usedbytes = $qinfo{$this}{PcentBytesUsed};
        my $hused     = $qinfo{$this}{HumanBytesUsed};
        my $hlimit    = $qinfo{$this}{HumanBytesLimit};
        $qcount++;
        $exitcode = $plugin->check_threshold( check => $usedbytes, warning => $warning, critical => $critical );
        if ( $exitcode != OK ) {
            $plugin->add_message( $exitcode, "$tree: $hused/$hlimit ($usedbytes%)." );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        $plugin->add_message( OK, "$qcount tree byte quotas, $qunlim unlimited quotas." );
    }
}

sub checkTreeFileQuotas {
    my %qinfo = getQuotaInfo();
    my ( $errorcount, $qcount, $qunlim ) = ( 0, 0, 0 );
    foreach my $this ( keys %qinfo ) {
        next if $qinfo{$this}{Type} != 3;
        if ( $qinfo{$this}{FilesUnlimited} == 2 ) {
            $qunlim++;
            next;
        }
        my $tree      = $qinfo{$this}{QTree};
        my $usedfiles = $qinfo{$this}{PcentFilesUsed};
        my $hused     = $qinfo{$this}{FilesUsed};
        my $hlimit    = $qinfo{$this}{FilesLimit};
        $qcount++;
        $exitcode = $plugin->check_threshold( check => $usedfiles, warning => $warning, critical => $critical );
        if ( $exitcode != OK ) {
            $plugin->add_message( $exitcode, "$tree: $hused/$hlimit ($usedfiles%)." );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        $plugin->add_message( OK, "$qcount tree file quotas, $qunlim unlimited quotas." );
    }
}

sub checkUptime {
    my ( $exitcode, $message );
    $session->translate(0);
    my $rawuptime = snmpGetRequest( "$baseOID.1.2.1.1.0", "uptime", 0 );
    $rawuptime = int( $rawuptime / 100 );
    my $uptime = parse_duration("$rawuptime seconds");
    $exitcode = $plugin->check_threshold( check => $rawuptime / 3600, warning => $warning, critical => $critical );
    $message = "System uptime is " . duration( $uptime, 3 ) . '.';
    $plugin->add_message( $exitcode, $message );
}

sub checkUserByteQuotas {
    my %qinfo = getQuotaInfo();
    my ( $errorcount, $qcount, $qunlim ) = ( 0, 0, 0 );
    foreach my $this ( keys %qinfo ) {
        next if ( $qinfo{$this}{Type} != 1 || $qinfo{$this}{Type} != 4 );
        if ( $qinfo{$this}{BytesUnlimited} == 2 ) {
            $qunlim++;
            next;
        }
        my $user      = $qinfo{$this}{RealID};
        my $usedbytes = $qinfo{$this}{PcentBytesUsed};
        my $hused     = $qinfo{$this}{HumanBytesUsed};
        my $hlimit    = $qinfo{$this}{HumanBytesLimit};
        $qcount++;
        $exitcode = $plugin->check_threshold( check => $usedbytes, warning => $warning, critical => $critical );
        if ( $exitcode != OK ) {
            $plugin->add_message( $exitcode, "$user: $hused/$hlimit ($usedbytes%)." );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        $plugin->add_message( OK, "$qcount user byte quotas, $qunlim unlimited quotas." );
    }
}

sub checkUserFileQuotas {
    my %qinfo = getQuotaInfo();
    my ( $errorcount, $qcount, $qunlim ) = ( 0, 0, 0 );
    foreach my $this ( keys %qinfo ) {
        next if ( $qinfo{$this}{Type} != 2 || $qinfo{$this}{Type} != 5 );
        if ( $qinfo{$this}{FilesUnlimited} == 2 ) {
            $qunlim++;
            next;
        }
        my $user      = $qinfo{$this}{RealID};
        my $usedfiles = $qinfo{$this}{PcentFilesUsed};
        my $hused     = $qinfo{$this}{FilesUsed};
        my $hlimit    = $qinfo{$this}{FilesLimit};
        $qcount++;
        $exitcode = $plugin->check_threshold( check => $usedfiles, warning => $warning, critical => $critical );
        if ( $exitcode != OK ) {
            $plugin->add_message( $exitcode, "$user: $hused/$hlimit ($usedfiles%)." );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        $plugin->add_message( OK, "$qcount user file quotas, $qunlim unlimited quotas." );
    }
}

sub checkVolumeBytes {
    my %dfinfo = getDiskSpaceInfo();
    my ( $errorcount, $volcount ) = ( 0, 0 );
    foreach my $this ( keys %dfinfo ) {
        next if ( $dfinfo{$this}{isAggregate} == 1 || $dfinfo{$this}{isSnapshot} == 1 );
        my $usedbytes = $dfinfo{$this}{PcentUsedBytes} || "0";
        my $hused     = $dfinfo{$this}{HumanUsedBytes};
        my $htotal    = $dfinfo{$this}{HumanTotalBytes};
        my $name      = $dfinfo{$this}{Name};
        $volcount++;
        $exitcode = $plugin->check_threshold( check => $usedbytes, warning => $warning, critical => $critical );
        if ( $exitcode != OK ) {
            $plugin->add_message( $exitcode, "Volume \'$name\' byte use is $hused/$htotal ($usedbytes%)." );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        my $message = "$volcount volume";
        $message .= $volcount == 1 ? ' is OK' : 's are OK';
        $message .= '.';
        $plugin->add_message( OK, $message );
    }
}

sub checkVolumeInodes {
    my %dfinfo = getDiskSpaceInfo();
    my ( $errorcount, $volcount ) = ( 0, 0 );
    foreach my $this ( keys %dfinfo ) {
        next if ( $dfinfo{$this}{isAggregate} == 1 || $dfinfo{$this}{isSnapshot} == 1 );
        my $usedinodes = $dfinfo{$this}{PcentUsedInodes} || "0";
        my $used       = $dfinfo{$this}{UsedInodes};
        my $total      = $dfinfo{$this}{TotalInodes};
        my $name       = $dfinfo{$this}{Name};
        $volcount++;
        $exitcode = $plugin->check_threshold( check => $usedinodes, warning => $warning, critical => $critical );
        if ( $exitcode != OK ) {
            $plugin->add_message( $exitcode, "Volume \'$name\' inode use is $used/$total ($usedinodes%)." );
            $errorcount++;
        }
    }

    if ( $errorcount == 0 ) {
        my $message = "$volcount volume";
        $message .= $volcount == 1 ? ' is OK' : 's are OK';
        $message .= '.';
        $plugin->add_message( OK, $message );
    }
}

sub getClusteredFailoverInfo {
    my %cfinfo = ();
    for ( my $oid = 1 ; $oid <= 8 ; $oid++ ) {
        my $data = snmpGetRequest( "$baseOID.1.2.3.$oid.0", "CF OID $oid", 0 );
        if ( $oid == 1 ) { $cfinfo{Settings}                = $data; }
        if ( $oid == 2 ) { $cfinfo{State}                   = $data; }
        if ( $oid == 3 ) { $cfinfo{CannotTakeoverCause}     = $data; }
        if ( $oid == 4 ) { $cfinfo{PartnerStatus}           = $data; }
        if ( $oid == 5 ) { $cfinfo{PartnerLastStatusUpdate} = $data; }
        if ( $oid == 6 ) { $cfinfo{PartnerName}             = $data; }
        if ( $oid == 7 ) { $cfinfo{PartnerSysid}            = $data; }
        if ( $oid == 8 ) { $cfinfo{InterconnectStatus}      = $data; }
    }
    return %cfinfo;
}

sub getDiskHealthInfo {
    my %dhinfo = ();
    for ( my $oid = 1 ; $oid <= 11 ; $oid++ ) {
        my $data = snmpGetRequest( "$baseOID.1.6.4.$oid.0", "disk OID $oid", 0 );
        if ( $oid == 1 )  { $dhinfo{Total}                = $data; }
        if ( $oid == 2 )  { $dhinfo{Active}               = $data; }
        if ( $oid == 3 )  { $dhinfo{Reconstructing}       = $data; }
        if ( $oid == 4 )  { $dhinfo{ReconstructingParity} = $data; }
        if ( $oid == 5 )  { $dhinfo{VerifyingParity}      = $data; }
        if ( $oid == 6 )  { $dhinfo{Scrubbing}            = $data; }
        if ( $oid == 7 )  { $dhinfo{Failed}               = $data; }
        if ( $oid == 8 )  { $dhinfo{Spare}                = $data; }
        if ( $oid == 9 )  { $dhinfo{AddingSpare}          = $data; }
        if ( $oid == 10 ) { $dhinfo{FailedMessage}        = $data; }
        if ( $oid == 11 ) { $dhinfo{Prefailed}            = $data; }
    }
    return %dhinfo;
}

sub getDiskSpaceInfo {
    my $result = snmpGetTable( "$baseOID.1.5.4", "disk usage information", 0 );
    my %dfinfo = ();
    foreach my $line ( keys %{$result} ) {
        my @data  = split /\./, $line;
        my $item  = $data[11];
        my $fs    = $data[12];
        my $value = $result->{$line};
        if ( $item == 2 ) { $dfinfo{$fs}{Name} = $value; $dfinfo{$fs}{isSnapshot} = isSnapshot($value); }
        if ( $item == 7 )  { $dfinfo{$fs}{UsedInodes}   = $value; }
        if ( $item == 8 )  { $dfinfo{$fs}{FreeInodes}   = $value; }
        if ( $item == 20 ) { $dfinfo{$fs}{Status}       = $value; $dfinfo{$fs}{StatusText} = volumeStatusLookup($value); }
        if ( $item == 21 ) { $dfinfo{$fs}{MirrorStatus} = $value; $dfinfo{$fs}{MirrorStatusText} = volumeMirrorStatusLookup($value); }
        if ( $item == 23 ) { $dfinfo{$fs}{Type}         = $value; $dfinfo{$fs}{TypeText} = volumeTypeLookup($value); }
        if ( $item == 29 ) { $dfinfo{$fs}{TotalBytes}   = $value * 1024; }
        if ( $item == 30 ) { $dfinfo{$fs}{UsedBytes}    = $value * 1024; }
        if ( $item == 31 ) { $dfinfo{$fs}{FreeBytes}    = $value * 1024; }
    }

    foreach my $fs ( keys %dfinfo ) {
        $dfinfo{$fs}{HumanTotalBytes} = format_bytes( $dfinfo{$fs}{TotalBytes} );
        $dfinfo{$fs}{HumanUsedBytes}  = format_bytes( $dfinfo{$fs}{UsedBytes} );
        $dfinfo{$fs}{HumanFreeBytes}  = format_bytes( $dfinfo{$fs}{FreeBytes} );
        $dfinfo{$fs}{TotalInodes}     = $dfinfo{$fs}{UsedInodes} + $dfinfo{$fs}{FreeInodes};
        if ( $dfinfo{$fs}{isSnapshot} == 0 ) {
            eval {
                $dfinfo{$fs}{PcentUsedBytes}  = sprintf( "%.3f", $dfinfo{$fs}{UsedBytes} / $dfinfo{$fs}{TotalBytes} * 100 );
                $dfinfo{$fs}{PcentUsedInodes} = sprintf( "%.3f", $dfinfo{$fs}{UsedInodes} / $dfinfo{$fs}{TotalInodes} * 100 );
                $dfinfo{$fs}{PcentUsedBytes}  += 0;
                $dfinfo{$fs}{PcentUsedInodes} += 0;

            };
        }
        $dfinfo{$fs}{isAggregate} = $dfinfo{$fs}{Type} == 3 ? 1 : 0;
    }
    return %dfinfo;
}

sub getEnclosureInfo {
    my %encinfo = ();
    my $result = snmpGetTable( "$baseOID.1.21.1.2", "enclosure info", 0 );
    foreach my $line ( keys %{$result} ) {
        my @data  = split /\./, $line;
        my $item  = $data[12];
        my $enc   = $data[13];
        my $value = $result->{$line};

        if ( $item == 2 )  { $encinfo{$enc}{ContactState}                = $value; }
        if ( $item == 3 )  { $encinfo{$enc}{ChannelShelfAddr}            = $value; }
        if ( $item == 4 )  { $encinfo{$enc}{ProductLogicalID}            = $value; }
        if ( $item == 5 )  { $encinfo{$enc}{ProductID}                   = $value; }
        if ( $item == 6 )  { $encinfo{$enc}{ProductVendor}               = $value; }
        if ( $item == 7 )  { $encinfo{$enc}{ProductModel}                = $value; }
        if ( $item == 8 )  { $encinfo{$enc}{ProductRevision}             = $value; }
        if ( $item == 9 )  { $encinfo{$enc}{ProductSerialNo}             = $value; }
        if ( $item == 10 ) { $encinfo{$enc}{NumberDiskBays}              = $value; }
        if ( $item == 11 ) { $encinfo{$enc}{DisksPresent}                = $value; }
        if ( $item == 12 ) { $encinfo{$enc}{PowerSuppliesMaximum}        = $value; }
        if ( $item == 13 ) { $encinfo{$enc}{PowerSuppliesPresent}        = $value; }
        if ( $item == 14 ) { $encinfo{$enc}{PowerSuppliesSerialNos}      = $value; }
        if ( $item == 15 ) { $encinfo{$enc}{PowerSuppliesFailed}         = $value; }
        if ( $item == 16 ) { $encinfo{$enc}{FansMaximum}                 = $value; }
        if ( $item == 17 ) { $encinfo{$enc}{FansPresent}                 = $value; }
        if ( $item == 18 ) { $encinfo{$enc}{FansFailed}                  = $value; }
        if ( $item == 19 ) { $encinfo{$enc}{TempSensorsMaximum}          = $value; }
        if ( $item == 20 ) { $encinfo{$enc}{TempSensorsPresent}          = $value; }
        if ( $item == 21 ) { $encinfo{$enc}{TempSensorsOverTempFail}     = $value; }
        if ( $item == 22 ) { $encinfo{$enc}{TempSensorsOverTempWarn}     = $value; }
        if ( $item == 23 ) { $encinfo{$enc}{TempSensorsUnderTempFail}    = $value; }
        if ( $item == 24 ) { $encinfo{$enc}{TempSensorsUnderTempWarn}    = $value; }
        if ( $item == 25 ) { $encinfo{$enc}{TempSensorsCurrentTemp}      = $value; }
        if ( $item == 26 ) { $encinfo{$enc}{TempSensorsOverTempFailThr}  = $value; }
        if ( $item == 27 ) { $encinfo{$enc}{TempSensorsOverTempWarnThr}  = $value; }
        if ( $item == 28 ) { $encinfo{$enc}{TempSensorsUnderTempFailThr} = $value; }
        if ( $item == 29 ) { $encinfo{$enc}{TempSensorsUnderTempWarnThr} = $value; }
        if ( $item == 30 ) { $encinfo{$enc}{ElectronicsMaximum}          = $value; }
        if ( $item == 31 ) { $encinfo{$enc}{ElectronicsPresent}          = $value; }
        if ( $item == 32 ) { $encinfo{$enc}{ElectronicsSerialNos}        = $value; }
        if ( $item == 33 ) { $encinfo{$enc}{ElectronicsFailed}           = $value; }
        if ( $item == 34 ) { $encinfo{$enc}{VoltSensorsMaximum}          = $value; }
        if ( $item == 35 ) { $encinfo{$enc}{VoltSensorsPresent}          = $value; }
        if ( $item == 36 ) { $encinfo{$enc}{VoltSensorsOverVoltFail}     = $value; }
        if ( $item == 37 ) { $encinfo{$enc}{VoltSensorsOverVoltWarn}     = $value; }
        if ( $item == 38 ) { $encinfo{$enc}{VoltSensorsUnderVoltFail}    = $value; }
        if ( $item == 39 ) { $encinfo{$enc}{VoltSensorsUnderVoltWarn}    = $value; }
        if ( $item == 40 ) { $encinfo{$enc}{VoltSensorsOverVoltFailThr}  = $value; }
        if ( $item == 41 ) { $encinfo{$enc}{VoltSensorsOverVoltWarnThr}  = $value; }
        if ( $item == 42 ) { $encinfo{$enc}{VoltSensorsUnderVoltFailThr} = $value; }
        if ( $item == 43 ) { $encinfo{$enc}{VoltSensorsUnderVoltWarnThr} = $value; }
        if ( $item == 44 ) { $encinfo{$enc}{VoltSensorsCurrentVolt}      = $value; }
        if ( $item == 45 ) { $encinfo{$enc}{CurSensorsMaximum}           = $value; }
        if ( $item == 46 ) { $encinfo{$enc}{CurSensorsPresent}           = $value; }
        if ( $item == 47 ) { $encinfo{$enc}{CurSensorsOverCurFail}       = $value; }
        if ( $item == 48 ) { $encinfo{$enc}{CurSensorsOverCurWarn}       = $value; }
        if ( $item == 49 ) { $encinfo{$enc}{CurSensorsOverCurFailThr}    = $value; }
        if ( $item == 50 ) { $encinfo{$enc}{CurSensorsOverCurWarnThr}    = $value; }
        if ( $item == 51 ) { $encinfo{$enc}{CurSensorsCurrentCur}        = $value; }
        if ( $item == 52 ) { $encinfo{$enc}{SASConnectMaximum}           = $value; }
        if ( $item == 53 ) { $encinfo{$enc}{SASConnectPresent}           = $value; }
        if ( $item == 54 ) { $encinfo{$enc}{SASConnectVendor}            = $value; }
        if ( $item == 55 ) { $encinfo{$enc}{SASConnectType}              = $value; }
        if ( $item == 56 ) { $encinfo{$enc}{SASConnectCableLen}          = $value; }
        if ( $item == 57 ) { $encinfo{$enc}{SASConnectCableTech}         = $value; }
        if ( $item == 58 ) { $encinfo{$enc}{SASConnectCableEnd}          = $value; }
        if ( $item == 59 ) { $encinfo{$enc}{SASConnectSerialNos}         = $value; }
        if ( $item == 60 ) { $encinfo{$enc}{SASConnectPartNos}           = $value; }
        if ( $item == 61 ) { $encinfo{$enc}{PowerSuppliesPartNos}        = $value; }
        if ( $item == 62 ) { $encinfo{$enc}{FansSpeed}                   = $value; }
        if ( $item == 63 ) { $encinfo{$enc}{ElectronicsPartNos}          = $value; }
        if ( $item == 64 ) { $encinfo{$enc}{ElectronicsCPLDVers}         = $value; }
    }

    my $tmps;
    my @tmpa;
    foreach my $this ( keys %encinfo ) {
        $tmps = $encinfo{$this}{PowerSuppliesPresent};
        $tmps =~ s/\s+//;
        @tmpa = split /,/, $tmps;
        $encinfo{$this}{PowerSuppliesPresentCount} = scalar @tmpa;
        $tmps = $encinfo{$this}{PowerSuppliesFailed};
        $tmps =~ s/\s+//;
        @tmpa = split /,/, $tmps;
        $encinfo{$this}{PowerSuppliesFailedCount} = scalar @tmpa;
        $tmps = $encinfo{$this}{FansPresent};
        $tmps =~ s/\s+//;
        @tmpa = split /,/, $tmps;
        $encinfo{$this}{FansPresentCount} = scalar @tmpa;
        $tmps = $encinfo{$this}{FansFailed};
        $tmps =~ s/\s+//;
        @tmpa = split /,/, $tmps;
        $encinfo{$this}{FansFailedCount} = scalar @tmpa;
    }
    return %encinfo;
}

sub getEnvironmentInfo {
    my %einfo = ();
    for ( my $oid = 1 ; $oid <= 5 ; $oid++ ) {
        my $data = snmpGetRequest( "$baseOID.1.2.4.$oid.0", "environment OID $oid", 0 );
        if ( $oid == 1 ) { $einfo{OverTemperature}  = $data; }
        if ( $oid == 2 ) { $einfo{FailedFanCount}   = $data; }
        if ( $oid == 3 ) { $einfo{FailedFanMessage} = $data; }
        if ( $oid == 4 ) { $einfo{FailedPSUCount}   = $data; }
        if ( $oid == 5 ) { $einfo{FailedPSUMessage} = $data; }
    }
    return %einfo;
}

sub getQuotaInfo {
    my $result = snmpGetTable( "$baseOID.1.4.6", "quota information", 1 );
    my %quotainfo = ();
    foreach my $line ( keys %{$result} ) {
        my @data   = split /\./, $line;
        my $item   = $data[11];
        my $vol    = $data[12];
        my $idx    = $data[13];
        my $volidx = $vol . "_" . $idx;
        my $value  = $result->{$line};
        if ( $item == 2 ) { $quotainfo{$volidx}{Type} = $value; $quotainfo{$volidx}{TypeText} = quotaTypeLookup($value); }
        if ( $item == 3 ) { $quotainfo{$volidx}{ID} = $value; }
        if ( $item == 6 )  { $quotainfo{$volidx}{BytesUnlimited} = $value; }
        if ( $item == 9 )  { $quotainfo{$volidx}{FilesUsed}      = $value; }
        if ( $item == 10 ) { $quotainfo{$volidx}{FilesUnlimited} = $value; }
        if ( $item == 11 ) { $quotainfo{$volidx}{FilesLimit}     = $value; }
        if ( $item == 12 ) { $quotainfo{$volidx}{PathName}       = $value; }
        if ( $item == 14 ) { $quotainfo{$volidx}{QTree}          = $value; }
        if ( $item == 15 ) { $quotainfo{$volidx}{IDType}         = $value; }
        if ( $item == 16 ) { $quotainfo{$volidx}{SID}            = $value; }
        if ( $item == 25 ) { $quotainfo{$volidx}{BytesUsed}      = $value; }
        if ( $item == 26 ) { $quotainfo{$volidx}{BytesLimit}     = $value; }
    }

    foreach my $this ( keys %quotainfo ) {
        $quotainfo{$this}{HumanBytesUsed}  = format_bytes( $quotainfo{$this}{BytesUsed} );
        $quotainfo{$this}{HumanBytesLimit} = format_bytes( $quotainfo{$this}{BytesLimit} );
        eval {
            $quotainfo{$this}{PcentBytesUsed} = sprintf( "%.3f", $quotainfo{$this}{BytesUsed} / $quotainfo{$this}{BytesLimit} * 100 );
            $quotainfo{$this}{PcentFilesUsed} = sprintf( "%.3f", $quotainfo{$this}{FilesUsed} / $quotainfo{$this}{FilesLimit} * 100 );
        };
        $quotainfo{$this}{RealID} = '<Unknown>';
        if ( $quotainfo{$this}{IDType} == 1 ) { $quotainfo{$this}{RealID} = $quotainfo{$this}{ID}; }
        if ( $quotainfo{$this}{IDType} == 2 ) { $quotainfo{$this}{RealID} = $quotainfo{$this}{SID}; }
    }
    return %quotainfo;
}

sub getSnapshotInfo {
    my $result = snmpGetTable( "$baseOID.1.5.5.2", "snapshot information", 0 );
    my %snapshotinfo = ();
    foreach my $line ( keys %{$result} ) {
        my @data   = split /\./, $line;
        my $item   = $data[12];
        my $vol    = $data[13];
        my $idx    = $data[14];
        my $volidx = $vol . "_" . $idx;
        my $value  = $result->{$line};
        if ( $item == 2 )  { $snapshotinfo{$volidx}{Month}      = $value; }
        if ( $item == 3 )  { $snapshotinfo{$volidx}{Day}        = $value; }
        if ( $item == 4 )  { $snapshotinfo{$volidx}{Hour}       = $value; }
        if ( $item == 5 )  { $snapshotinfo{$volidx}{Minutes}    = $value; }
        if ( $item == 6 )  { $snapshotinfo{$volidx}{Name}       = $value; }
        if ( $item == 7 )  { $snapshotinfo{$volidx}{Volume}     = $value; }
        if ( $item == 8 )  { $snapshotinfo{$volidx}{Number}     = $value; }
        if ( $item == 9 )  { $snapshotinfo{$volidx}{VolumeName} = $value; }
        if ( $item == 10 ) { $snapshotinfo{$volidx}{Type}       = $value; }
    }
    return %snapshotinfo;
}

sub quotaTypeLookup {
    my $value = shift;
    my %map   = (
        1 => 'user',
        2 => 'group',
        3 => 'tree',
        4 => 'userdefault',
        5 => 'groupdefault',
        6 => 'unknown',
    );
    return $map{$value};
}

sub volumeMirrorStatusLookup {
    my $value = shift;
    my %map   = (
        1  => 'invalid',
        2  => 'uninitialized',
        3  => 'needcpcheck',
        4  => 'cpcheckwait',
        5  => 'unmirrored',
        6  => 'normal',
        7  => 'degraded',
        8  => 'resyncing',
        9  => 'failed',
        10 => 'limbo',
    );
    return $map{$value};
}

sub volumeStatusLookup {
    my $value = shift;
    my %map   = (
        1  => 'unmounted',
        2  => 'mounted',
        3  => 'frozen',
        4  => 'destroying',
        5  => 'creating',
        6  => 'mounting',
        7  => 'unmounting',
        8  => 'nofsinfo',
        9  => 'replaying',
        10 => 'replayed',
    );
    return $map{$value};
}

sub volumeTypeLookup {
    my $value = shift;
    my %map   = (
        1 => 'traditional',
        2 => 'flexible',
        3 => 'aggregate',
    );
    return $map{$value};
}

sub snmpGetRequest {
    my ( $oid, $itemdesc, $undef_on_fail ) = @_;
    my $result = $session->get_request("$oid");
    if ( $undef_on_fail == 0 ) {
        $plugin->nagios_exit( UNKNOWN, "Cannot read $itemdesc ($oid): " . $session->error ) unless defined $result;
    }
    my $data = $result->{"$oid"} // undef;
    return $data;
}

sub snmpGetTable {
    my ( $oid, $itemdesc, $undef_on_fail ) = @_;
    my $result = $session->get_table("$oid");
    if ( $undef_on_fail == 0 ) {
        $plugin->nagios_exit( UNKNOWN, "Cannot read $itemdesc ($oid): " . $session->error ) unless defined $result;
    }
    return $result;
}

sub isSnapshot {
    my $name = shift;
    return $name =~ /\/\.snapshot$/ ? 1 : 0;
}

sub enclosuresPresent {
    my $enccount = snmpGetRequest( "$baseOID.1.21.1.1.0", "enclosure count", 0 );
    if ( $enccount == 0 ) {
        $plugin->add_message( OK, 'No enclosures present.' );
    }
    return $enccount;
}

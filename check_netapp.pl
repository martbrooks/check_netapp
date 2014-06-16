#!/usr/bin/perl

use strict;
use warnings;

use Cwd 'abs_path';
use File::Basename;
use Getopt::Long::Descriptive;
use Nagios::Plugin;
use Nagios::Plugin qw(%STATUS_TEXT);
use Net::SNMP;
use Number::Bytes::Human qw(format_bytes parse_bytes);
use Switch::Plain;
use Time::Duration;
use Time::Duration::Parse;
use YAML::XS qw(DumpFile LoadFile);

my $VERSION='2014061600';

my ( $opt, $usage ) = describe_options(
	"%c (ver. $VERSION) %o",
	['Plugin parameters:'],
		['hostname|h=s'  => 'NetApp hostname or IP.',   { required => 1 } ],
		['community|C=s' => 'SNMP community string.', { required => 1, default => 'public' }],
		['help'          => 'Print help and usage.' ],
	[],
	['Nagios parameters:'],
		['warning|w=s'  => 'Sets the warning threshold for the check.'],
		['critical|c=s' => 'Sets the critical threshold for the check.'],
	[],
	['Available Metrics:'],
		['metric|m=s' => hidden => { one_of =>[
			['aggregatebytes'  => 'Check aggregate byte usage.'],
			['aggregateinodes' => 'Check aggregate inode usage.'],
			['diskhealth'      => 'Check physical disk health.'],
			['nvrambattery'    => 'Check NVRAM battery status.'],
			['treefilequotas'  => 'Check tree file quotas.'],
			['treebytequotas'  => 'Check tree byte quotas.'],
			['uptime'          => 'Check system uptime.'],
			['userfilequotas'  => 'Check user file quotas.'],
			['userbytequotas'  => 'Check user byte quotas.'],
			['volumebytes'     => 'Check volume byte usage.'],
			['volumeinodes'    => 'Check volume inode usage.'],
	]}],
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

if ($opt->help || $metric eq ''){
        print $usage->text;
        exit;
}

my $config=dirname(abs_path($0))."/check_netapp_config.yaml";
my $yaml;
if (-e "$config"){
        $yaml=LoadFile("$config");
}

$hostname=lc($hostname);
if ($yaml->{hostmap}->{$hostname}){
        $hostname=lc($yaml->{hostmap}->{$hostname});
}

my $plugin = Nagios::Plugin->new;
my $baseOID = '1.3.6.1.4.1.789';

my ($session,$error ) = Net::SNMP->session(
	-hostname  => "$hostname",
	-community => "$community",
	-timeout   => 30,
	-version   => 'snmpv2c'
);
$plugin->nagios_exit(UNKNOWN, "Could not create SNMP session to $hostname" ) unless $session;

my ($warnneeded,$critneeded)=(0,0);
sswitch($metric){
	case 'aggregatebytes'   : { $warnneeded=1; $critneeded=1; }
	case 'aggregateinodes'  : { $warnneeded=1; $critneeded=1; }
	case 'treebytequotas'   : { $warnneeded=1; $critneeded=1; }
	case 'treefilequotas'   : { $warnneeded=1; $critneeded=1; }
	case 'uptime        '   : { $warnneeded=1; $critneeded=1; }
	case 'userbytequotas'   : { $warnneeded=1; $critneeded=1; }
	case 'userfilequotas'   : { $warnneeded=1; $critneeded=1; }
	case 'volumebytes'      : { $warnneeded=1; $critneeded=1; }
	case 'volumeinodes'     : { $warnneeded=1; $critneeded=1; }
}

if ($warnneeded && !defined($warning)){
        $plugin->nagios_exit(UNKNOWN, "The $metric check requires a warning threshold.");
}

if ($critneeded && !defined($critical)){
        $plugin->nagios_exit(UNKNOWN, "The $metric check requires a critical threshold.");
}

sswitch($metric){
	case 'aggregatebytes'  : { checkAggregateBytes()  }
	case 'aggregateinodes' : { checkAggregateInodes() }
	case 'diskhealth'      : { checkDiskHealth()      }
	case 'nvrambattery'    : { checkNVRAMBattery()    }
	case 'treebytequotas'  : { checkTreeByteQuotas()  }
	case 'treefilequotas'  : { checkTreeFileQuotas()  }
	case 'uptime'          : { checkUptime()          }
	case 'userbytequotas'  : { checkUserByteQuotas()  }
	case 'userfilequotas'  : { checkUserFileQuotas()  }
	case 'volumebytes'     : { checkVolumeBytes()     }
	case 'volumeinodes'    : { checkVolumeInodes()    }
	default                : { $plugin->add_message(CRITICAL,"No handler found for metric $metric."); }
}

my ($exitcode,$message)=$plugin->check_messages;
$plugin->nagios_exit($exitcode,$message);

sub checkNVRAMBattery{
	my $exitcode;
	my $result = $session->get_request("$baseOID.1.2.5.1.0");
	$plugin->nagios_exit(UNKNOWN, "Cannot read NVRAM battery status " . $session->error ) unless defined $result;
	my $data=$result->{"$baseOID.1.2.5.1.0"};
	my $message='NVRAM battery is ';
	nswitch ($data){
		case 1 : { $message.='OK';                   $exitcode=OK;       }
		case 2 : { $message.='partially discharged'; $exitcode=WARNING;  }
		case 3 : { $message.='full discharged';      $exitcode=CRITICAL; }
		case 4 : { $message.='not present';          $exitcode=WARNING;  }
		case 5 : { $message.='near end of life';     $exitcode=WARNING;  }
		case 6 : { $message.='at end of life';       $exitcode=CRITICAL; }
		case 7 : { $message.='unknown';              $exitcode=WARNING;  }
		case 8 : { $message.='overcharged';          $exitcode=WARNING;  }
		case 9 : { $message.='fully charged';        $exitcode=WARNING;  }
	}
	$message.='.';
	$plugin->add_message($exitcode,$message);
}

sub checkDiskHealth{
	my ($exitcode,$message);
	my $errorcount=0;
	my %dhinfo=getDiskHealthInfo();

	if ($dhinfo{Failed}>0){
		$errorcount++;
		$plugin->add_message(CRITICAL, $dhinfo{Failed} . " failed disks: $dhinfo{FailedMessage}");
	}

	if ($dhinfo{Reconstructing}>0){
		$errorcount++;
		$plugin->add_message(WARNING, $dhinfo{Reconstructing} . ' disk(s) reconstructing.');
	}

	if ($dhinfo{ReconstructingParity}>0){
		$errorcount++;
		$plugin->add_message(WARNING, $dhinfo{ReconstructingParity} . ' disk(s) parity reconstructing.');
	}

	if ($dhinfo{AddingSpare}>0){
		$errorcount++;
		$plugin->add_message(WARNING, $dhinfo{AddingSpare} . ' spare disk(s) being added.');
	}

	if ($errorcount==0){
		$plugin->add_message(OK,"$dhinfo{Total} disks present, $dhinfo{Active} active.");
	}
}

sub checkUptime{
        my ($exitcode,$message);
	my $result = $session->get_request("$baseOID.1.2.1.1.0");
	$plugin->nagios_exit(UNKNOWN, "Cannot check uptime: " . $session->error ) unless defined $result;
	my $rawuptime=$result->{"$baseOID.1.2.1.1.0"};
	$rawuptime=~s/\.\d\d$//;
	my $uptime=parse_duration($rawuptime);
	$exitcode = $plugin->check_threshold(check => $uptime/3600, warning => $warning, critical => $critical);
	$message="System uptime is " . duration($uptime) . '.';
	$plugin->add_message($exitcode,$message);
}

sub checkAggregateBytes{
	my %dfinfo=getDiskSpaceInfo();
	my ($errorcount,$aggcount)=(0,0);
	foreach my $this (keys %dfinfo){
		next if ($dfinfo{$this}{isAggregate}==0 || $dfinfo{$this}{isSnapshot}==1);
		my $usedbytes=$dfinfo{$this}{PcentUsedBytes};
		my $hused=$dfinfo{$this}{HumanUsedBytes};
		my $htotal=$dfinfo{$this}{HumanTotalBytes};
		my $name=$dfinfo{$this}{Name};
		$aggcount++;
		$exitcode = $plugin->check_threshold(check => $usedbytes, warning => $warning, critical => $critical);
		if ($exitcode != OK){
			$plugin->add_message($exitcode,"Aggregate \'$name\' byte use is $hused/$htotal ($usedbytes%).");
			$errorcount++;
		}
	}

	if ($errorcount == 0){
		$plugin->add_message(OK,"$aggcount aggregates OK.");
	}
}

sub checkAggregateInodes{
	my %dfinfo=getDiskSpaceInfo();
	my ($errorcount,$aggcount)=(0,0);
	foreach my $this (keys %dfinfo){
		next if ($dfinfo{$this}{isAggregate}==0 || $dfinfo{$this}{isSnapshot}==1);
		my $usedinodes=$dfinfo{$this}{PcentUsedInodes};
		my $used=$dfinfo{$this}{UsedInodes};
		my $total=$dfinfo{$this}{TotalInodes};
		my $name=$dfinfo{$this}{Name};
		$aggcount++;
		$exitcode = $plugin->check_threshold(check => $usedinodes, warning => $warning, critical => $critical);
		if ($exitcode != OK){
			$plugin->add_message($exitcode,"Aggregate \'$name\' inode use is $used/$total ($usedinodes%).");
			$errorcount++;
		}
	}

	if ($errorcount == 0){
		$plugin->add_message(OK,"$aggcount aggregates OK.");
	}
}

sub checkVolumeBytes{
	my %dfinfo=getDiskSpaceInfo();
	my ($errorcount,$volcount)=(0,0);
	foreach my $this (keys %dfinfo){
		next if ($dfinfo{$this}{isAggregate}==1 || $dfinfo{$this}{isSnapshot}==1);
		my $usedbytes=$dfinfo{$this}{PcentUsedBytes};
		my $hused=$dfinfo{$this}{HumanUsedBytes};
		my $htotal=$dfinfo{$this}{HumanTotalBytes};
		my $name=$dfinfo{$this}{Name};
		$volcount++;
		$exitcode = $plugin->check_threshold(check => $usedbytes, warning => $warning, critical => $critical);
		if ($exitcode != OK){
			$plugin->add_message($exitcode,"Volume \'$name\' byte use is $hused/$htotal ($usedbytes%).");
			$errorcount++;
		}
	}

	if ($errorcount == 0){
		$plugin->add_message(OK,"$volcount volumes OK.");
	}
}

sub checkVolumeInodes{
	my %dfinfo=getDiskSpaceInfo();
	my ($errorcount,$volcount)=(0,0);
	foreach my $this (keys %dfinfo){
		next if ($dfinfo{$this}{isAggregate}==1 || $dfinfo{$this}{isSnapshot}==1);
		my $usedinodes=$dfinfo{$this}{PcentUsedInodes};
		my $used=$dfinfo{$this}{UsedInodes};
		my $total=$dfinfo{$this}{TotalInodes};
		my $name=$dfinfo{$this}{Name};
		$volcount++;
		$exitcode = $plugin->check_threshold(check => $usedinodes, warning => $warning, critical => $critical);
		if ($exitcode != OK){
			$plugin->add_message($exitcode,"Volume \'$name\' inode use is $used/$total ($usedinodes%).");
			$errorcount++;
		}
	}

	if ($errorcount == 0){
		$plugin->add_message(OK,"$volcount volumes OK.");
	}
}

sub checkTreeByteQuotas{
	my %qinfo=getQuotaInfo();
	my ($errorcount,$qcount,$qunlim)=(0,0,0);
	foreach my $this (keys %qinfo){
		next if $qinfo{$this}{Type}!=3;
		if ($qinfo{$this}{BytesUnlimited}==2){
			$qunlim++;
			next;
		}
		my $tree=$qinfo{$this}{QTree};
		my $usedbytes=$qinfo{$this}{PcentBytesUsed};
		my $hused=$qinfo{$this}{HumanBytesUsed};
		my $hlimit=$qinfo{$this}{HumanBytesLimit};
		$qcount++;
		$exitcode = $plugin->check_threshold(check => $usedbytes, warning => $warning, critical => $critical);
		if ($exitcode != OK){
			$plugin->add_message($exitcode,"$tree: $hused/$hlimit ($usedbytes%).");
			$errorcount++;
		}
	}

	if ($errorcount == 0){
		$plugin->add_message(OK,"$qcount tree byte quotas OK, $qunlim unlimited quotas.");
	}
}

sub checkTreeFileQuotas{
	my %qinfo=getQuotaInfo();
	my ($errorcount,$qcount,$qunlim)=(0,0,0);
	foreach my $this (keys %qinfo){
		next if $qinfo{$this}{Type}!=3;
		if ($qinfo{$this}{FilesUnlimited}==2){
			$qunlim++;
			next;
		}
		my $tree=$qinfo{$this}{QTree};
		my $usedfiles=$qinfo{$this}{PcentFilesUsed};
		my $hused=$qinfo{$this}{FilesUsed};
		my $hlimit=$qinfo{$this}{FilesLimit};
		$qcount++;
		$exitcode = $plugin->check_threshold(check => $usedfiles, warning => $warning, critical => $critical);
		if ($exitcode != OK){
			$plugin->add_message($exitcode,"$tree: $hused/$hlimit ($usedfiles%).");
			$errorcount++;
		}
	}

	if ($errorcount == 0){
		$plugin->add_message(OK,"$qcount tree file quotas OK, $qunlim unlimited quotas.");
	}
}

sub checkUserByteQuotas{
	my %qinfo=getQuotaInfo();
	my ($errorcount,$qcount,$qunlim)=(0,0,0);
	foreach my $this (keys %qinfo){
		next if ($qinfo{$this}{Type}!=1 || $qinfo{$this}{Type}!=4);
		if ($qinfo{$this}{BytesUnlimited}==2){
			$qunlim++;
			next;
		}
		my $user=$qinfo{$this}{RealID};
		my $usedbytes=$qinfo{$this}{PcentBytesUsed};
		my $hused=$qinfo{$this}{HumanBytesUsed};
		my $hlimit=$qinfo{$this}{HumanBytesLimit};
		$qcount++;
		$exitcode = $plugin->check_threshold(check => $usedbytes, warning => $warning, critical => $critical);
		if ($exitcode != OK){
			$plugin->add_message($exitcode,"$user: $hused/$hlimit ($usedbytes%).");
			$errorcount++;
		}
	}

	if ($errorcount == 0){
		$plugin->add_message(OK,"$qcount tree user quotas OK, $qunlim unlimited quotas.");
	}
}

sub checkUserFileQuotas{
	my %qinfo=getQuotaInfo();
	my ($errorcount,$qcount,$qunlim)=(0,0,0);
	foreach my $this (keys %qinfo){
		next if ($qinfo{$this}{Type}!=2 || $qinfo{$this}{Type}!=5);
		if ($qinfo{$this}{FilesUnlimited}==2){
			$qunlim++;
			next;
		}
		my $user=$qinfo{$this}{RealID};
		my $usedfiles=$qinfo{$this}{PcentFilesUsed};
		my $hused=$qinfo{$this}{FilesUsed};
		my $hlimit=$qinfo{$this}{FilesLimit};
		$qcount++;
		$exitcode = $plugin->check_threshold(check => $usedfiles, warning => $warning, critical => $critical);
		if ($exitcode != OK){
			$plugin->add_message($exitcode,"$user: $hused/$hlimit ($usedfiles%).");
			$errorcount++;
		}
	}

	if ($errorcount == 0){
		$plugin->add_message(OK,"$qcount user file quotas OK, $qunlim unlimited quotas.");
	}
}


sub getQuotaInfo{
        my $result = $session->get_table("$baseOID.1.4.6");
        $plugin->nagios_exit(UNKNOWN, "Cannot read quota information: " . $session->error ) unless defined $result;
	my %quotainfo=();
	foreach my $line (keys %{$result}){
		my @data=split/\./,$line;
		my $item=$data[11];
		my $vol=$data[12];
		my $idx=$data[13];
		my $volidx=$vol . "_" . $idx;
		my $value=$result->{$line};
		nswitch ($item){
			case  2 : { $quotainfo{$volidx}{Type}=$value; $quotainfo{$volidx}{TypeText}=quotaTypeLookup($value); }
			case  3 : { $quotainfo{$volidx}{ID}=$value; }
			case  6 : { $quotainfo{$volidx}{BytesUnlimited}=$value; }
			case  9 : { $quotainfo{$volidx}{FilesUsed}=$value; }
			case 10 : { $quotainfo{$volidx}{FilesUnlimited}=$value; }
			case 11 : { $quotainfo{$volidx}{FilesLimit}=$value; }
			case 12 : { $quotainfo{$volidx}{PathName}=$value; }
			case 14 : { $quotainfo{$volidx}{QTree}=$value; }
			case 15 : { $quotainfo{$volidx}{IDType}=$value; }
			case 16 : { $quotainfo{$volidx}{SID}=$value; }
			case 25 : { $quotainfo{$volidx}{BytesUsed}=$value; }
			case 26 : { $quotainfo{$volidx}{BytesLimit}=$value; }
		}
	}

	foreach my $this (keys %quotainfo){
		$quotainfo{$this}{HumanBytesUsed}=format_bytes($quotainfo{$this}{BytesUsed});
		$quotainfo{$this}{HumanBytesLimit}=format_bytes($quotainfo{$this}{BytesLimit});
		eval {
			$quotainfo{$this}{PcentBytesUsed}=sprintf("%.3f",$quotainfo{$this}{BytesUsed}/$quotainfo{$this}{BytesLimit}*100);
			$quotainfo{$this}{PcentFilesUsed}=sprintf("%.3f",$quotainfo{$this}{FilesUsed}/$quotainfo{$this}{FilesLimit}*100);
		};
		$quotainfo{$this}{RealID}='<Unknown>';
		nswitch($quotainfo{$this}{IDType}){
			case 1 : { $quotainfo{$this}{RealID}=$quotainfo{$this}{ID}; }
			case 2 : { $quotainfo{$this}{RealID}=$quotainfo{$this}{SID}; }
		}
	}

	return %quotainfo;
}

sub getDiskSpaceInfo{
        my $result = $session->get_table("$baseOID.1.5.4");
        $plugin->nagios_exit(UNKNOWN, "Cannot read disk usage information: " . $session->error ) unless defined $result;
	my %dfinfo=();
	foreach my $line (keys %{$result}){
		my @data=split/\./,$line;
		my $item=$data[11];
		my $fs=$data[12];
		my $value=$result->{$line};
		nswitch ($item){
			case  2 : { $dfinfo{$fs}{Name}=$value; $dfinfo{$fs}{isSnapshot}=isSnapshot($value);}
			case  7 : { $dfinfo{$fs}{UsedInodes}=$value; }
			case  8 : { $dfinfo{$fs}{FreeInodes}=$value; }
			case 20 : { $dfinfo{$fs}{Status}=$value; $dfinfo{$fs}{StatusText}=volumeStatusLookup($value);}
			case 21 : { $dfinfo{$fs}{MirrorStatus}=$value; $dfinfo{$fs}{MirrorStatusText}=volumeMirrorStatusLookup($value);}
			case 23 : { $dfinfo{$fs}{Type}=$value; $dfinfo{$fs}{TypeText}=volumeTypeLookup($value);}
			case 29 : { $dfinfo{$fs}{TotalBytes}=$value*1024; }
			case 30 : { $dfinfo{$fs}{UsedBytes}=$value*1024; }
			case 31 : { $dfinfo{$fs}{FreeBytes}=$value*1024; }
		}
	}

	foreach my $fs (keys %dfinfo){
		$dfinfo{$fs}{HumanTotalBytes}=format_bytes($dfinfo{$fs}{TotalBytes});
		$dfinfo{$fs}{HumanUsedBytes}=format_bytes($dfinfo{$fs}{UsedBytes});
		$dfinfo{$fs}{HumanFreeBytes}=format_bytes($dfinfo{$fs}{FreeBytes});
		$dfinfo{$fs}{TotalInodes}=$dfinfo{$fs}{UsedInodes}+$dfinfo{$fs}{FreeInodes};
		if ($dfinfo{$fs}{isSnapshot}==0){
			eval {
				$dfinfo{$fs}{PcentUsedBytes}=sprintf("%.3f",$dfinfo{$fs}{UsedBytes}/$dfinfo{$fs}{TotalBytes}*100);
				$dfinfo{$fs}{PcentUsedInodes}=sprintf("%.3f",$dfinfo{$fs}{UsedInodes}/$dfinfo{$fs}{TotalInodes}*100);
			};
		}
		$dfinfo{$fs}{isAggregate}=$dfinfo{$fs}{Type}==3?1:0
	}

	return %dfinfo;
}

sub volumeStatusLookup{
	my $value=shift;
	my $text='';
	nswitch ($value){
		case  1 : { $text='unmounted';  }
		case  2 : { $text='mounted';    }
		case  3 : { $text='frozen';     }
		case  4 : { $text='destroying'; }
		case  5 : { $text='creating';   }
		case  6 : { $text='mounting';   }
		case  7 : { $text='unmounting'; }
		case  8 : { $text='nofsinfo';   }
		case  9 : { $text='replaying';  }
		case 10 : { $text='replayed';   }
	}
	return $text;
}

sub volumeMirrorStatusLookup{
	my $value=shift;
	my $text='';
	nswitch ($value){
		case  1 : { $text='invalid';       }
		case  2 : { $text='uninitialized'; }
		case  3 : { $text='needcpcheck';   }
		case  4 : { $text='cpcheckwait';   }
		case  5 : { $text='unmirrored';    }
		case  6 : { $text='normal';        }
		case  7 : { $text='degraded';      }
		case  8 : { $text='resyncing';     }
		case  9 : { $text='failed';        }
		case 10 : { $text='limbo';         }
	}
	return $text;
}

sub volumeTypeLookup{
	my $value=shift;
	my $text='';
	nswitch ($value){
		case 1 : { $text='traditional'; }
		case 2 : { $text='flexible';    }
		case 3 : { $text='aggregate';   }
	}
	return $text;
}

sub isSnapshot{
	my $name=shift;
	return $name=~/\/\.snapshot$/?1:0;
}

sub quotaTypeLookup{
	my $value=shift;
	my $text='';
	nswitch ($value){
		case 1 : { $text='user';         }
		case 2 : { $text='group';        }
		case 3 : { $text='tree';         }
		case 4 : { $text='userdefault';  }
		case 5 : { $text='groupdefault'; }
		case 6 : { $text='unknown';      }
	}
	return $text;
}


sub getDiskHealthInfo{
	my %dhinfo=();
	for (my $oid=1; $oid<=11; $oid++){
		my $result = $session->get_request("$baseOID.1.6.4.$oid.0");
		$plugin->nagios_exit(UNKNOWN, "Cannot read disk OID $oid: " . $session->error ) unless defined $result;
		my $data=$result->{"$baseOID.1.6.4.$oid.0"};
		nswitch ($oid){
			case  1 : { $dhinfo{Total}=$data;                }
			case  2 : { $dhinfo{Active}=$data;               }
			case  3 : { $dhinfo{Reconstructing}=$data;       }
			case  4 : { $dhinfo{ReconstructingParity}=$data; }
			case  5 : { $dhinfo{VerifyingParity}=$data;      }
			case  6 : { $dhinfo{Scrubbing}=$data;            }
			case  7 : { $dhinfo{Failed}=$data;               }
			case  8 : { $dhinfo{Spare}=$data;                }
			case  9 : { $dhinfo{AddingSpare}=$data;          }
			case 10 : { $dhinfo{FailedMessage}=$data;        }
			case 11 : { $dhinfo{Prefailed}=$data;            }
		}
	}
	return %dhinfo;
}

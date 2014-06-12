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
use YAML::XS qw(DumpFile LoadFile);

my $VERSION='2014061100';

my ( $opt, $usage ) = describe_options(
	"%c (ver. $VERSION) %o",
	['Plugin parameters:'],
		['hostname|h=s'  => 'HNAS hostname or IP.',   { required => 1 } ],
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
			['volumebytes'     => 'Check aggregate byte usage.'],
			['volumeinodes'    => 'Check aggregate inode usage.'],
	]}],
	[],
	['Example usage:'],
		["$0 --hostname 1.2.3.4 --warning 70 --critical 90 --aggregates"],
		["$0 -h 1.2.3.4 -w 70 -c 90 --aggregates"],
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
        case 'volumebytes'     : { checkVolumeBytes()     }
        case 'volumeinodes'    : { checkVolumeInodes()    }
        default                : { $plugin->add_message(CRITICAL,"No handler found for metric $metric."); }
}

my ($exitcode,$message)=$plugin->check_messages;
$plugin->nagios_exit($exitcode,$message);

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
			case 20 : { $dfinfo{$fs}{Status}=$value; $dfinfo{$fs}{StatusText}=statusLookup($value);}
			case 21 : { $dfinfo{$fs}{MirrorStatus}=$value; $dfinfo{$fs}{MirrorStatusText}=mirrorStatusLookup($value);}
			case 23 : { $dfinfo{$fs}{Type}=$value; $dfinfo{$fs}{TypeText}=typeLookup($value);}
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
			$dfinfo{$fs}{PcentUsedBytes}=sprintf("%.3f",$dfinfo{$fs}{UsedBytes}/$dfinfo{$fs}{TotalBytes}*100);
			$dfinfo{$fs}{PcentUsedInodes}=sprintf("%.3f",$dfinfo{$fs}{UsedInodes}/$dfinfo{$fs}{TotalInodes}*100);
		}
		$dfinfo{$fs}{isAggregate}=$dfinfo{$fs}{Type}==3?1:0
	}

	return %dfinfo;
}

sub statusLookup{
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

sub mirrorStatusLookup{
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

sub typeLookup{
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

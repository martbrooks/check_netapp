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
			['vvolcapacity' => 'Virtual volume capacity and free space.'],
	]}],
	[],
	['Example usage:'],
		["$0 --hostname 1.2.3.4 --warning 70 --critical 90 --cpu"],
		["$0 -h 1.2.3.4 -w 70 -c 90 --cpu"],
	[],
);

my $community = $opt->community;
my $critical  = $opt->critical;
my $filter    = $opt->filter;
my $hostname  = $opt->hostname;
my $metric    = $opt->metric || '';
my $password  = $opt->password;
my $username  = $opt->username;
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

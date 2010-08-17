#!/usr/bin/perl
#---------------
# DoS Boot
# Detects and bans DoS attack sources
# created by: Ryan DeShone
#---------------
use strict;
use Getopt::Long;

#Configuration Variables
#-----------------------
my $stime = 30;
my $maxconn = 100;
my $maxban = 500;
#-----------------------

#---------------------------------------------
# There is no need to edit anything past this.
#---------------------------------------------

#Version Number
#--------------
my $vnum = "0.3.0";
#--------------

# Define subroutines
sub search;
sub checkban;
sub doban ($);
sub unban ($);
sub pout;
sub help;
sub genwhitelist;
####################

# Important files
my $confpath = "/etc/dosboot";
my $whitelist = "whitelist.dosboot";
my $logfile = "/var/log/dosboot.log";
#################

#Make sure we are running as root or none of the important stuff will work
if ($> != 0){
	print "DosBoot must be run as root!\n\tQuitting...\n";
	exit -1;
}

#Command line switches
my $list=0; my $help=0; my $debug=0; my $genwl=0;

#Parse command line options
my $result;
$result = GetOptions("list|l" => \$list,
		"help|h|?" => \$help,
		"debug|d" => \$debug,
		"maxban=i" => \$maxban,
		"maxcon=i" => \$maxconn,
		"genwhitelist|g" => \$genwl);

if($debug){print "list = $list\nhelp = $help\n";}

if($help){
	help();
	exit;
}

#Check if conf directory exists. Create it if not.
unless(-d "$confpath"){
	print "Creating $confpath\n";
	mkdir("$confpath",0750);
}
unless(-e "$confpath/$whitelist" && $genwl==0){
	print "Generating whitelist\n";
	genwhitelist();
	if($genwl != 0){
		print "Generated new whitelist\n";
		exit;
	}
}

#Attempt to detect APF or CSF, fall back on iptables if necessary
my ($PREBAN, $POSTBAN, $PREUBAN, $POSTUBAN);
my $uban = 0;
if (system("apf > /dev/null 2>&1") == 0){
	$PREBAN = "apf -d";
	$POSTBAN = "";
	$PREUBAN = "apf -u";
	$POSTUBAN = "";
	$uban = 1;
	print "Using apf to ban IPs\n";
}elsif(system("csf > /dev/null 2>&1") == 0){
	$PREBAN = "csf -d";
	$POSTBAN = "";
	print "Using csf to ban IPs\n";
}else{
	$PREBAN = "/sbin/iptables -I INPUT -s";
	$POSTBAN = "-j DROP";
	$PREUBAN = "/sbin/iptables -D INPUT -s";
	$POSTUBAN = "-j DROP";
	$uban = 1;
	print "Falling back on iptables for bans\n";
}

##############################################
# Load whitelist so we don't ban the wrong IPs
##############################################

my @WHITELIST;
open(WL, "$confpath/$whitelist") or die "Unable to open $whitelist : $!";
while(<WL>){
	my $line = $_;
	chomp($line);
	unless($line =~ m/^#/) {
		if ($line =~ /^*([1-2]*[0-9]*[0-9]\.[1-2]*[0-9]*[0-9]\.[1-2]*[0-9]*[0-9]\.[1-2]*[0-9]*[0-9]).*$/){
			push @WHITELIST, $line;
		}
	}
}
if($debug){print "Whitelist array:\n@WHITELIST\n";}
close(WL);

##############################################
# The most important part of the script,
# the endless program loop of banning goodness
##############################################

while (1){
	search();
	if($list){
		pout();
		exit;
	}
	checkban();
	sleep($stime);
}
#End of the most important part of the script.

#Variables to store data, no touchy
my (@DATA, %CONINFO, @BANLIST);
my $totban = 0;
my $banpos = 0;

###############################
# Subroutines past this point #
###############################

################################
#
# Gather and parse data
#
################################

sub search {
	chomp(@DATA = qx!/bin/netstat -nt!);
	shift(@DATA);shift(@DATA);
	while (@DATA){
		my $t = shift(@DATA);
		my ($prot,$recvq,$sendq,$local,$remote,$state) = split(" ", $t);
		$remote =~ s/::ffff://g;
		my ($remoteip,$remoteport) = split(":", $remote);
		if($CONINFO{$remoteip}){
			$CONINFO{$remoteip}++;
		}else{
			$CONINFO{$remoteip} .= 1;
		}
	}
}

######################################
#
# Print a table of IPs and the number
# of connections currently open
#
######################################

sub pout{
	print "-------------------------------------------------\n";
	print "|Source IP\t\t\t|Connections\t|\n";
	print "-------------------------------------------------\n";
	foreach my $ip (sort keys %CONINFO) {
		print "|$ip       \t\t|$CONINFO{$ip}\t\t|\n";
	}
	print "-------------------------------------------------\n";
}

############################################
#
# Print a helpful help message. For helping.
#
############################################

sub help{

	print "DoS-Boot v. $vnum\n
		Usage:\tdosboot.pl OPTIONS\n
		Options:
		--genwhitelist,-g\t Regenerate the automatic whitelist
		\t\tCAUTION: This will overwrite the current whitelist
		--help,-h\tPrint this helpful help message\n
		--list,-l\tPrint out list of connected IPs and the number of open connections
		--maxban=n\tMaximum number of IPs to ban before removing old bans
		\t\tCurrently only works with apf
		--maxcon=n\tMaximum number of connections before banning IP\n";

}

#######################################
#
# Check IP table for naughty IPs to ban
#
#######################################

sub checkban {
	foreach my $ip (sort keys %CONINFO) {
		if ($CONINFO{$ip} >= $maxconn){
			unless ( grep ( /$ip$/,@BANLIST ) > 0 || grep ( /$ip$/,@WHITELIST ) > 0 ){
				if ($totban >= $maxban && $uban == 1){
					print "Removing $BANLIST[$banpos] from firewall.\n";
					unban ($BANLIST[$banpos]);
				}
				print "Blocking $ip with $CONINFO{$ip} connections.\n";
				doban ($ip);
				$BANLIST[$banpos]="$ip";
				$banpos = ($banpos + 1) % $maxban;
				$totban++;
			}
		}
	}
}

#################################
#
# Do the actual banning of the IP
#
#################################

sub doban ($){
	my ($ip) = @_;
	my $rc = system("$PREBAN $ip $POSTBAN");
	if($rc != 0){
		print "Banning IP failed, bugging out.\n";
		exit $rc;
	}
}

############################################
#
# Attempt to remove blocked IP from firewall
#
############################################

sub unban ($){
	my ($ip) = @_;
	my $rc = system("$PREUBAN $ip $POSTUBAN");
	if($rc != 0){
		print "Unbanning IP failed, bugging out.\n";

		if($debug != 0){print "DEBUG INFO:
	UBAN IP = $ip
	totban = $totban
	banpos = $banpos
	maxban = $maxban\n";}
		
		exit $rc;
	}
}

#################################################
#
# Autogenerates a whitelist containing the IPs 
# currently assigned to the server
#
#################################################

sub genwhitelist {
	unless (-e "$confpath/$whitelist"){
		print "Creating whitelist at $confpath/$whitelist\n";
		open(WL, ">$confpath/$whitelist") or die "Can't create $whitelist : $!";
	}
	my @DATA;
	chomp(@DATA = qx!/sbin/ifconfig -a | grep "inet addr"!);
	while(@DATA){
		my $t = shift(@DATA);
		my ($a,$addr) = split(" ",$t);
		$addr =~ s/::ffff://g;
		my ($b,$ip) = split(":",$addr);
		print WL "$ip\n";
	}
	close(WL);
}

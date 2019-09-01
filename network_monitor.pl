#!/usr/bin/perl

#-- Script used for network monitoring.. will be expanded upon when I feel like it

#-------------#
use strict;
use warnings;
use Getopt::Long;
use Term::ANSIColor;

no warnings 'uninitialized';
#-------------#

system('clear');


#-- Usage menu
sub help{
    system("clear");
    print color('bright_magenta');
    print "+=+=+=+=+=+=+=+=+=+=++=+=+=+=\n";
    print "Network info gather... er\n";
    print "+=+=+=+=+=+=+=+=+=+=++=+=+=+=\n";
    print color('reset');
    print color('bright_cyan');
    print "-h Print this page\n";
    print "Optional: -i or --interface={interface} - default: eth0\n";
    print "Optional: -t or --time={seconds} - default: -t=15\n";
    print "Example: perl bandwidth-checker.pl -i=eth0 -t=15\n";
    print color('reset');
    exit;
}


#-- Standard variables
my($org, $csv, $help, $time, $interface, $mode);

$time = 15;
$interface = 'eth0';

#-- function for processing command line arguments
GetOptions(
    "t|time:i"        => \$time,
    "i|interface:s"   => \$interface,
    "h|help"          => \$help
);

if ($help){
    help();
    exit;
}

#-- Interface information
my($inet, $netmask, $broadcast);
my $me = `whoami`;
my $config = `ifconfig $interface | grep -P "([0-9]{1,3}\.){3}[0-9]{1,3}"`;

if ($config =~ /\w+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\w+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\w+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
    $inet = $1;
    $netmask = $2;
    $broadcast = $3;
}

print color('bright_yellow');
print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n";
print "[+] Welcome $me";
print "[+] Monitoring interface: $interface\n";
print color('bright_red');
print "[+] ONLY WORKS WITH IPv4!!\n[+] NO FILTERING IS IN PLACE FOR IPv6!!\n";
print color('bright_yellow');
print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n";
print color('bright_cyan');
print "[+] IPv4: $inet\n";
print "[+] Netmask: $netmask\n";
print "[+] Broadcast: $broadcast\n";
print color('bright_yellow');
print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n";
print color('reset');

#-------------------#
&avg_rtx;
&active_conn;
print color('bright_cyan'),"+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n";
#------------------#

sub avg_rtx {
    my ($initialrx, $initialtx, $finalrx, $finaltx);
    #Gets a line indicating the current usage.
    my $bytes1 = `ifconfig $interface | grep -P "[R|T]X .*? bytes"`;
    
    #strip it into variables for recieved and transmitted
    if ($bytes1 =~ m/[RX]+\s+.*?(?:\d+\s+\w+)\s+(\d+)\s+\(.*?\)\s+[TX]+\s+.*?(?:\d+\s+\w+)\s+(\d+)/g) {
        $initialrx = $1 * 8;
        $initialtx = $2 * 8;    
    } 
    #wait x seconds and run the command again.
    sleep($time);
    #Gets a line indicating the current usage.
    my $bytes2 = `ifconfig $interface | grep -P "[R|T]X .*? bytes"`;
    if ($bytes2 =~ m/[RX]+\s+.*?(?:\d+\s+\w+)\s+(\d+)\s+\(.*?\)\s+[TX]+\s+.*?(?:\d+\s+\w+)\s+(\d+)/g) {
        $finalrx = $1 * 8;
        $finaltx = $2 * 8;    
    }
    
    my $differencerx = ($finalrx - $initialrx) / $time;
    my $differencetx = ($finaltx - $initialtx) / $time;
    my($kbitpsrx,$kbitpstx,$KBpsrx,$KBpstx,$kbitrx,$kbittx,$KBrx,$KBtx);
    $kbitpsrx = $differencerx / 1024;
    $kbitpstx = $differencetx / 1024;
    $KBpsrx = $differencerx / 1024 / 8;
    $KBpstx = $differencetx / 1024 / 8;
    $kbitrx = ($finalrx - $initialrx) / 1024;
    $kbittx = ($finaltx - $initialtx) / 1024;
    $KBrx = ($finalrx - $initialrx) / 1024 / 8;
    $KBtx = ($finaltx - $initialtx) / 1024 / 8;
    print color('bright_red');
    print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n";
    print "[+] Monitored traffic for $time seconds\n";
    print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n";
    print "[+] Incoming: $kbitrx kbit ($KBrx KB) Average: $kbitpsrx kbps ($KBpsrx KBps)\n";
    print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n";
    print "[+] Outgoing: $kbittx kbit ($KBtx KB) Average: $kbitpstx kbps ($KBpstx KBps)\n";
    print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n";
    print color('reset');
    
}


#-- This whole subroutine needs to be re-worked
sub active_conn {
    my $active = `netstat -ano`;
    my @lports;
    my @fports;
    my @hosts;

    #-- I could condense this down to one loop and do better filtering.. I'm lazy.. so fuck it, copy pasta it is

    while ($active =~ m/(?:0\.0\.0\.0|127\.0\.0\.1|$inet)\W\K(\d+\s+)/g){
        my @local_ports = split /\n/, $1;
        
        my %lfiltered = map {$_, 1} @local_ports;
        
        my @lfiltered = keys %lfiltered;
       
        foreach (@lfiltered) {
            chomp $_;
            push @lports, $_;
        }
        
    }


    while ($active =~ m/(?:0\.0\.0\.0|127\.0\.0\.1|$inet)(?:.*?)\K(?:[1-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3})\K(\d+)/g){
        my @foreign_ports = split /\n/, $1;
        
        my %ffiltered = map {$_, 1} @foreign_ports;
        
        my @ffiltered = keys %ffiltered;
       
        foreach (@ffiltered) {
            chomp $_;
            push @fports, $_;
        }
        
    }

    while ($active =~ m/(?:0\.0\.0\.0|127\.0\.0\.1|$inet)(?:.*?)\K([1-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3})/g) {
        my @conn_hosts = split /\n/, $1;
        
        my %hfiltered = map {$_, 1} @conn_hosts;
        
        my @hfiltered = keys %hfiltered;
       
        foreach (@hfiltered) {
            chomp $_;
            push @hosts, $_;
        }
    }

    print color('bright_cyan'),"+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n[+] Checking ESTABLISHED port connections\n";
    foreach (@lports) {
        print color('bright_blue');
        print "[+] LOCAL open port found: $_\n";
    }

    foreach (@fports) {
        print color('bright_red');
        print "[+] Established FOREIGN port connection: $_\n";
    }


    #-- A bit buggy
    print color('bright_magenta'),"+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n[+] Checking ESTABLISHED connections\n";
    foreach (@hosts) {
        print color('bright_red');
        print "[+] Established FOREIGN connections: $_\n";
    }
}

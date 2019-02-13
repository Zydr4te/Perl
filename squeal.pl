#!/usr/bin/perl

#-- SQLi testing tool (work in progress)

use strict;
use warnings;
use HTTP::Cookies;
use LWP::UserAgent;
use LWP::Protocol::https;
use Term::ANSIColor;
#---------------------#
my $usage = "USAGE: perl squeal.pl [Target URI]\n";
my $target = shift || die $usage;
#---------------------#
#-- Bot building for things
my $cookie = new HTTP::Cookies(ignore_discard => 1);
my $bot = LWP::UserAgent->new(keep_alive => 1);
$bot -> timeout(10);
$bot -> agent("Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US; rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18");
$bot -> cookie_jar($cookie);
#---------------------#
#-- Manipulating the inputted url to add HTTP if it is not present and remove a trailing slash
if ($target !~ /http:\/\//) {$target = "http://$target";}
$target = $1 if($target =~/(.*)\/$/);
#---------------------#
#-- Some Global stuff
my @content;
my @get;
#---------------------#
#-- Banner
print color('bright_magenta');
print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
print "Testing for SQLi on $target\n";
print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
print color('reset');
#---------------------#
content_find();
#---------------------#
#-- Filter for files
{
	foreach (@content) {
		if ($_ =~ m/<a.*href=("|')([^"']+)("|')/){
			print color('bold green'), "[+] Found file: $2\n", color('reset');
			GET_filter($2);
		}
	}
	last;
}
#---------------------#
#-- Checking if there are files with GET
if (scalar @get > 0) {
	print color('bold green');
	print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
	print "Mangling the URL!!\n";
	print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
	mangle_url();
}
else {
	print color('bright_red');
	print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
	print "No valid parameters found!!\n";
	print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
}
#---------------------#
#-- Finding content
sub content_find {
file_find();
}

#-- Filtering for GET requests
sub GET_filter {
	my $file = shift;
	if ($file =~ m/\?[^=]+=[get]+/i){
		push @get, $file;
	}
}

#-- Mangling URL
sub mangle_url {
		foreach my $getUrl (@get) {
		my $url = $_;
		$url =~ s/(\?id[^=]+=) [0-9a-z_]/$1%27/;
		print color
		sql_test($url);
	}
}

#-- Finding a vulnerability
sub sql_test {
	my $test = shift;
	my $res = $bot -> get($target) -> content;
	if ($res =~ m/error.*syntax.*sql/i) {
		print color('bright_green');
		print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
		print "SQLi confirmed at $res\n";
		print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
	}
}

#-- finding individual content
sub file_find {
	my $res = $bot -> get($target);
	if ($res -> is_success) {
		@content = split(/\015?\012/, $res -> content);
	}
}

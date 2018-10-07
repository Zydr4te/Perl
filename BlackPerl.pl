#!/usr/bin/perl

################################
#
# A full scale Web Hacking toolkit (Version 0.2.1)
#
# I am NOT Responsible for misuse of this tool
#
# Under HEAVY developement
#
################################
# Version Notes
#
#
# Version 0.2.1:
# Began work on directory traversal
#
# Version 0.2.0:
#	DNS options have been included. TO BE ADDED: Zone Transfers
#
# Version 0.1.6:
#	Minor adjustments to menu
#
# Version 0.1.5:
#	Made it so that the links from the spider output to the screen
#
# Version 0.1.4:
#	Added an option for DNS attacks, began development on Google Dorking
#
# Version 0.1.3:
#	Added an additional catch to the spider
#
# Version 0.1.2:
#	Fixed issue where script would close after one use
#
# Version 0.1.1:
#	Added additional functionality to the spider to save links
#
# Version 0.1.0:
#	Basic web spider functionality added
#
# Version 0.0.3:
#	Added a check to see if the user is privileged
#
# Version 0.0.2:
#	Menu functionality completed
#
# Version 0.0.1:
# 	Skeleton added to the code
#################################
# Modules
use strict;
use warnings;
use WWW::Mechanize;
use LWP::UserAgent;
use Net::Whois::Raw;
use Net::DNS::Dig;
use URI::Escape;
use NetAddr::IP::Util qw(inet_ntoa);
################################
# Web Spider
my sub spider {
	system('clear');

	print "++++++++++++++++++++++++++++\n";
	print "+          Spider          +\n";
	print "++++++++++++++++++++++++++++\n";
	print "Enter the target domain: ";
	chomp (my $url = <STDIN>);

	my $file = "links.txt";

	if (-e $file) {exec("del links.txt");}

	my $spider = WWW::Mechanize -> new();

	$spider -> get($url);
	$spider -> agent_alias( 'Windows IE 6' );

	for my $link ($spider -> find_all_links()){
		open(my $fh, '>>', $file) || die $!;
		say $fh "URI: ", $link->url_abs. $/;
		say $fh "Title: ", $link->attrs->{title} || "[n/a]", $/, $/;
		if (open($fh, '<:encoding(UTF-8)', $file)){
			while (my $row = <$fh>) {
				chomp $row;
				print "$row\n";
			}
		}
		close $fh;
	}

	print "Created the file 'links.txt' which holds the results\n";

	sleep(3);
	print "++++++++++++++++++++++++++++\n";
	print "Press 'ENTER' to continue... ";
	<STDIN>;
}

# XSS scanner
my sub xss_scan {
	print "IN DEVELOPMENT\n";
}

# SQLi
my sub sqli_scan {
	print "IN DEVELOPMENT\n";
}

# Google dorking
my sub google_dork {
	system('clear');

	print "What is the url?: ";
	chomp(my $url = <STDIN>);

	my $file = "google.txt";

	if (-e $file) {exec("del google.txt");}

	my $google = 'https://google.com/search?q=' . $url;

	my $bot = WWW::Mechanize -> new;
}

# Directory Traversal
my sub directory_traversal {
	system('clear');

	my @paths = ( "/etc/passwd", "/etc/shadow", "/etc/hosts");

	print "++++++++++++++++++++++++++++++++++++++\n";
	print "+        Directory Traversal         +\n";
	print "++++++++++++++++++++++++++++++++++++++\n";
	print "+ 1: /etc/passwd                     +\n";
	print "+ 2: /etc/shadow                     +\n";
	print "+ 3: /etc/hosts                      +\n";
	print "++++++++++++++++++++++++++++++++++++++\n";
	print "+ What directory do you want?:        \n";
	chomp(my $dt = <STDIN>);
  print "++++++++++++++++++++++++++++++++++++++\n";
	print "+ What is the URL your going to?:     \n";
	chomp(my $url = <STDIN>);


}

# File inclusion
my sub file_inclusion {
	print "IN DEVELOPMENT\n";
}

# Banner grabbing
my sub banner_grab {
	print "IN DEVELOPMENT\n";
}

# Brute force
my sub brute_force {
	print "IN DEVELOPMENT\n";
}

#####################################################
# DNS based attacks
my sub dns_dig {
	print "++++++++++++++++++++++++++++\n";
	print "+          DNS DiG         +\n";
	print "++++++++++++++++++++++++++++\n";
	print "Enter the target domain: ";
	chomp (my $target = <STDIN>);

	my @targets = Net::DNS::Dig -> new() -> for ($target) ->rdata();

	foreach (@targets){
		print inet_ntoa($_),"\n";
	}

	print "++++++++++++++++++++++++++++\n";
	print "Press 'Enter' to continue...";
	<STDIN>;

}

my sub dns_whois {
	print "++++++++++++++++++++++++++++\n";
	print "+       WHOIS lookup       +\n";
	print "++++++++++++++++++++++++++++\n";
	print "Enter the target IP: ";
	chomp (my $target = <STDIN>);

	foreach (split(/\n/,whois($target))) {
		print $_,"\n" if(m/^(netrange|orgname)/i);
	}

	print "++++++++++++++++++++++++++++\n";
	print "Press 'Enter' to continue...";
	<STDIN>;
}


my sub dns_attacks{
	system('clear');
	#Menu for choosing DNS attacks
	print "++++++++++++++++++++++++++++\n";
	print "+       DNS ATTACKS        +\n";
	print "++++++++++++++++++++++++++++\n";
	print "+ 1: Whois lookup          +\n";
	print "+ 2: DNS DiG               +\n";
	print "++++++++++++++++++++++++++++\n";
	print "+ What do you want to do?: ";
	chomp(my $choice = <STDIN>);

	if ($choice eq '1'){dns_whois();}
	elsif ($choice eq '2'){dns_dig();}
	else{
		print "Not an option, try again: ";
		chomp($choice = <STDIN>);
	}
}

######################################################

# Menu
my sub menu {
	#Privilege check
	if ($< != 0) {
		print "You must be root to run this script!\n";
		exit(0);
	}

	system('clear');
	print "+++++++++++++++++++++++++++++      \n";
	print "+ 1: Spider                        \n";
	print "+ 2: XSS                 (dev)     \n";
	print "+ 3: SQLi                (dev)     \n";
	print "+ 4: Google Dorking      (dev)     \n";
	print "+ 5: Directory Traversal (dev)     \n";
	print "+ 6: File Inclusion      (dev)     \n";
	print "+ 7: Banner Grabbing     (dev)     \n";
	print "+ 8: Brute Forcing       (dev)     \n";
	print "+ 9: DNS attacks                   \n";
	print "+ 99: QUIT                         \n";
	print "+++++++++++++++++++++++++++++      \n";

	print "What do you want to do?: ";
	chomp(my $choice = <STDIN>);

	if    ($choice eq '1') {spider();}
	elsif ($choice eq '2') {xss_scan();}
	elsif ($choice eq '3') {sqli_scan();}
	elsif ($choice eq '4') {google_dork();}
	elsif ($choice eq '5') {directory_traversal();}
	elsif ($choice eq '6') {file_inclusion();}
	elsif ($choice eq '7') {banner_grab();}
	elsif ($choice eq '8') {brute_force();}
	elsif ($choice eq '9') {dns_attacks();}
	elsif ($choice eq '99'){
		print "Goodbye!!\n";
		sleep(2);
		system('reset');
		exit()
	}
	else {
		#Basic error checking
		print "Not a choice, try again: ";
		chomp($choice = <STDIN>);
	}
}

#Keeps the menu running when another subroutine finishes
while (1) {
	menu();
}

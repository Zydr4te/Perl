#!/usr/bin/env perl

use strict;
use warnings;
use LWP::UserAgent;
use LWP::Protocol::https;
use HTTP::Cookies;
use vars qw($cookies $bot %mail $res $b $url $t @emails $email);

$| = 1;

mine($ARGV[0]);

sub bot {

	$cookies = HTTP::Cookies->new;
	$bot = LWP::UserAgent -> new;
	$bot->agent('Mozilla/4.76 [en] (Win98; U)');
	$bot -> cookie_jar($cookies);
	$bot -> timeout(10);
	$bot ->show_progress(1);

	return $bot;
}

sub mine {

	$t = shift;

	unless($t) {
		die "usage: perl $0 <domain name>\nperl $0 example.com";
	}

	$url = 'https://www.google.com/search?num=100&start=0&h1=en&meta=&q=%40%22'.$t.'%22'; 

	$b = bot();

	$res = $b->get($url);

	if($res -> is_success) {
		@emails = $res->as_string =~ m/[a-z0-9_.-]+\@/ig;
		foreach $email (@emails) {
			if(not exists $mail{$email}) {
				print "Possible Email Match: ",$email, $t,"\n";
				$mail{$email} = 1; 
			}
		}
	} else {
		die $res ->status_line;
	}
}

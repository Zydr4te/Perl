#!/usr/bin/perl

use strict;
use warnings;
use LWP::UserAgent;
use LWP::Protocol::https;
use HTTP::Cookies;
use Term::ANSIColor;
$| = 1;

#
# Page resource locator
#
# Version 1.0
#

main($ARGV[0]);

sub main {
    my $target = shift;
    my $fixed = validate_target($target);
    my $b = bot();
    my $decoded = fetch($b, $target);
    parse($decoded, $fixed);
}


sub validate_target {
    my $t = shift;
    if($t =~ m/^(http|https):\/\/.*/g){
        return $t;
    }else {
        $t = "http://".$t;
        return $t;
    }
}

sub fetch {
    my($browser, $page) = @_;
    my $get = $browser->get($page);
    my $content = $get->decoded_content;
    return $content;

}

sub bot {
    my $cookies = HTTP::Cookies->new;
    my $bot = LWP::UserAgent->new;
    $bot->cookie_jar($cookies);
    $bot->timeout(10);
    $bot->show_progress(1);
    return $bot;
}

sub parse {
    my ($source, $home) = @_;
    my @line = split(/\n/, $source);
    my @found;
    for(@line){
        if($_ =~ m/^.*((?:http|https):\/\/.*\.[php|js|com|org|jpg|png]+).*/g){
            push @found, $1
        }
        if($_ =~ m/Incapsula_Resource/gi) {
            print color('bright_yellow'),"{!} INCAPSULA RESOURCE FOUND ON SITE\n";
        }
    }
    @found = do {my %seen; grep{ !$seen{$_}++ } @found};

    for(@found) {
        print color('bright_green'),"[+] Page Resource found: $_\n";
    }
}

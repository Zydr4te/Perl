#!/usr/bin/perl -T

=pod

=head1 TITLE
	LinkSpider
	

=head2 SYNOPSIS
	This script is designed to be a simple web crawler.
	The purpose is for basic reconnaissance, I am
	NOT RESPONSIBLE for the misuse of this tool

=head3 DETAILS
	This is Version 1.0. This is not user friendly.
	This spider will grab as much as information as possible.
	It also only scans one page
	This basic spider is also for my personal practice.

=cut

###Modules

use strict; #prevetns the script from running if there are issues
use warnings; #check the code for any issues
use WWW::Mechanize; #used for web crawling

###Gets the target URL from the user
print 'What is the URL you want to scrape? ';
chomp(my $url = <STDIN>);


###Handling Cookies
#cookie_jar => {}; #empty jar for handling cookies (Stored in memory)

###Building the spider
my $spider = WWW::Mechanize -> new(); #creates the spider

$spider -> get( $url ); #grabs the info from the provided URL

$spider -> agent_alias( 'Windows IE 6' ); #sets the alias for the spider

########################
# Available aliases    #
# Windows IE 6         #
# Windows Mozilla      #
# Mac Safari           #
# Mac Mozilla          #
# Linux Mozilla        #
# Linux Konqueror      #
########################

#file for saving the links
print 'Where do you want to save the links? (FULL PATH) ';
chomp(my $file = <STDIN>);
##


for my $link ($spider -> find_all_links())
{
	open(my $fh, '>>', $file) || die $!;
	say $fh "URI: ", $link->url_abs. $/;
	say $fh "Title: ", $link->attrs->{title} || "[n/a]", $/, $/;
	close $fh;
} 
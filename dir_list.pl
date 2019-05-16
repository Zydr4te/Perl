#!/usr/bin/env perl

use strict;
use warnings;
use Term::ANSIColor;

opendir(DIR, '<dir name here>') or die $!;

my @dirs;

while (my $dir = readdir DIR) {
	push @dirs, $dir;
}

closedir(DIR);

splice @dirs, 0, 1;
splice @dirs, 0, 1;

my $dircount = $#dirs + 1;

print color('green');
print "Total directories found: $dircount\n";
print "=====================\n";
foreach (@dirs){
	print "$_\n";
}
print color('reset');

#!/usr/bin/perl

use strict;
use warnings;

#-- Display Environment variables
foreach my $key (keys %ENV) {
    print "$key --> $ENV{$key}\n";
}

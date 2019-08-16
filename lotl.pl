#!/usr/bin/env perl

#-- Tool for quick plugin review
#-- Stands for "Lay Of The Land"

use strict;
use warnings;
use File::Find;
use Data::Dumper qw(Dumper);
#-- Sudo check
unless ($> == 0) {
    die "!!Must run as sudo!!\n";
}

#================#
#-- Command line parsing
use Getopt::Long;

my $path;

GetOptions ("path=s" => \$path);

unless (defined $path) {
    die "!!Please define path to plugin being tested!! (--path=/path/to/plugin)\n";
}
#================#

main();

#================#

sub main {

    `clear`;

    print "#====================================#\n";
    print "Begining recon...\n";
    #-- Get total number of directories and files
    my ($dcount, $fcount, @files) = file_count($path);
    print "#====================================#\n";
    print "Total directories found: $dcount\n";
    print "Total files found: $fcount\n";
    print "#====================================#\n";
    foreach (@files) {
        print "Potentially interesting file found: $_\n";
    }
    print "#====================================#\n";
    print "Starting keyword search...\n";
    print "#====================================#\n";
    my %kint = key_find(@files);
    while (my ($f, $p) = (each %kint)) {
      $p =~ s/^\s+|\s+$//g; #-- Gets rid of any leading or trailing spaces
        print "$p found in $f\n";
    }
    print "#====================================#\n";
    print "Starting database connection search...\n";
    print "#====================================#\n";
    db_conn(@files);
    print "#====================================#\n";
    print "Checking for sanitization...\n";
    my @us = haz_sanitize(keys %kint);
    if (scalar @us == 0) {
        print "All found files are sanitized... sadface\n";
    }
    foreach my $uf (@us) {
        print "No sanitization in the file $uf!\n";
    }
}

sub file_count {

    #-- Grab the target path
    my $dir = shift;

    #-- Placeholder arrays
    my @dirs;
    my @files;

    #-- Hunt for directories
    find(
        sub { push @dirs, $File::Find::name unless -f; },
        $dir
    );

    #-- Hunt for files
    find(
        sub { push @files, $File::Find::name unless -d; },
        $dir
    );

    #-- Strip away parent directory name
    splice @dirs, 0, 1;

    #-- Get the total count of directories and files
    my $dircount = scalar @dirs;
    my $filecount = scalar @files;


    my @pfiles = file_narrow(@files);


    return ($dircount, $filecount, @pfiles);

}


#-- Narrows down file search to just PHP files
sub file_narrow {

    my @file = @_;

    my @nfile;

    foreach my $e (@file) {
        if ($e =~ /.*php/) {
            push @nfile, $e;
        }
        else {
            next;
        }
    }

    return @nfile;

}

#-- Looks for keywords for potential vulnerability discovery
sub key_find {

    my @hunt = @_;

    my @interesting;

    my %key_match;

    my @keywords = qw(eval
    passthru
    system
    $_GET
    $_POST
    $_REQUEST);

    my @key_find;

    foreach my $h (@hunt) {
        chomp ($h);
        open(my $fh, '<', $h);
        while (my $r = <$fh>) {
            chomp($r);
            if (grep {$r =~ /$_/} @keywords) {
              $r = false_positive($r); #-- checks for false positives
              if (!defined $r) {
                next;
              }
              else {
                push @interesting, $h;
                push @key_find, $r;
              }
            }
        }
        close($fh);
        next;
    }

    @interesting = do {my %seen; grep { !$seen{$_}++ } @interesting};

    if (scalar @interesting == 0) {
      print "No keywords found\n";
    }

    @key_match{@interesting} = @key_find;

    return %key_match;

}

sub false_positive {
  my $f = shift;

  #-- I'll add more later

  if ($f =~ /eval[uation|ate]/g){
    return undef;
  }

}

#-- Checks for sanitizing functions
sub haz_sanitize {

    my @sfiles = @_;

    my @params = qw (
        htmlentities
        mysqli_real_escape_string
        mysql_real_escape_string
        trim
        addslashes
    );

    my (@sanitized, @unsanitized);

    foreach my $s (@sfiles) {
        chomp($s);
        open (my $f, '<', $s);
        while (my $r = <$f>) {
            if (grep {$r =~ /$_/} @params) {
                push @sanitized, $s;
            }
            else {
                push @unsanitized, $s;
            }
        }
        close($f);
    }

    @unsanitized = do {my %seen; grep { !$seen{$_}++ } @unsanitized};
    @sanitized = do {my %seen; grep { !$seen{$_}++ } @sanitized};

    return @unsanitized;
}

#-- Function for finding database connection strings to determine if this is vulnerable to SQLi
sub db_conn {

  my @dbfiles = @_;

  my @constring = qw (mysql_connect mysqli_connect PDO);

  my %conn_find;

  my @interesting;

  my @db_hit;

  foreach my $d (@dbfiles) {
    open(my $fh, '<', $d);
    while (my $r = <$fh>) {
        chomp($r);
        if (grep {$r =~ /.*$_/} @constring) {
          print "Database connection found in $d\n";
          last;
        } elsif (grep {$r !~ /.*$_/} @constring) {
          next;
        }
      }
      close($fh);
    }
    print "No database connection found\n";
}

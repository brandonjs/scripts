#!/usr/bin/perl -w

#use strict;                                                                              
#use warnings;                                                                            
                                                                                          
use Data::Dumper;                                                                         
use Carp qw(carp croak);                                                                  
use File::Find;
use Getopt::Std;

our ($opt_d, $opt_p);
die("ERROR: Invalid command line option.\n") unless getopts('d:p:');
die("ERROR: You must provide '-p' command line option.\n") if (!$opt_p);
die("ERROR: You must provide '-d' command line option.\n") if (!$opt_d);

my (@masterFileList, @distroFiles, @file_list, @dir_list, @filesToRemove);
my (%masterFileList, %distroFiles);
my $distro = lc($opt_d);
my $workingDir = ($opt_p);

$workingDir = $workingDir . "mirror/samaritan.ucmerced.edu/ubuntu";

die("ERROR: You must provide a valid path to your apt-mirror directory (e.g. /prj/qct/gv-ubuntu/apt-mirror).\n") if (! -d $workingDir);

sub subr1 {
    return unless /^Packages$/;
    return if ($File::Find::name =~ /$distro/);
    open FILE, "<Packages" or die "$!";
    my @lines = grep (/^Filename:/, <FILE>);
    close FILE;
    foreach my $line (@lines) { $line =~ s/Filename: //g; $line =~ s/^\s+//; $line =~ s/\s+$// }
    push (@masterFileList, @lines);
}

sub subr2 {
    return unless /^Packages$/;
    return unless ($File::Find::name =~ /$distro/);
    open FILE, "<Packages" or die "$!";
    my @lines = grep (/^Filename:/, <FILE>);
    close FILE;
    foreach my $line (@lines) { $line =~ s/Filename: //g; $line =~ s/^\s+//; $line =~ s/\s+$// }
    push (@distroFiles, @lines);
}

sub subr3 {
    return unless $File::Find::name =~ /$distro/;
    return if $File::Find::dir =~ /CVS/;
    print "$_\n";
    unlink if -f $_;
}

chdir($workingDir) or die "$!";

find(\&subr1, "./dists");
find(\&subr2, "./dists");

%masterFileList = map{$_ => 1} @masterFileList;
%distroFiles = map{$_ => 1} @distroFiles;

@filesToRemove = grep (!defined $masterFileList{$_}, @distroFiles);
foreach(@filesToRemove) { unlink $_ };

find(\&subr3, "./dists");

finddepth(sub{rmdir},'.')

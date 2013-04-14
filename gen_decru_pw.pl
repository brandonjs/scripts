#!/usr/local/bin/perl
use Crypt::Tea;
my $password = "";
my $key = "";

$password = encrypt($password,$key);
$password = unpack("H*",$password);

print "$password\n";

$password = pack("H*",$password);
$password = decrypt($password,$key);

print "$password\n";

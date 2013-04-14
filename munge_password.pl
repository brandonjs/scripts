#!/usr/local/bin/perl

#===============================================================================|
##   Perl modules.                                                              |
#===============================================================================|
use Cwd;
use Getopt::Std;
use File::Basename;
use Sys::Hostname;
use Date::Calc qw(:all);

## make sure configDir is set.
my $progName = basename($0);
my $configDir = dirname($0);
#===============================================================================|
# Several different files to open:
#   $inputFile  = Contains Qadmin information
#   $unameFile  = Contains uid and shell information. Keyed off e-mail address.
#   $outFile    = passwd file that is output for UNIX structure.
#   $cronFile   = Run out of cron that will set password expiration.
#   $decruFile  = A batch file to be passed to the decru_login.pl script to add 
#                   or remove users from the decru DFs.
#   $ahomeFile  = Automounter information for users mounts.
#===============================================================================|
my $inputFile = "$configDir/airlock.txt";
my $unameFile = "$configDir/usernames";
my $outFile = "/location/of/user/passwd";
my $cronFile = "/usr/local/etc/setup/cron/bin/chage";
my $decruScript = "/root/scripts/decru_login.pl";
my $decruFile = "$configDir/usermod";
my $ahomeFile = "/location/of/auto.home";
my $adminList = "$configDir/admins";
my $adminPasswd = "/location/of/admin/passwd";
my $gid = 10002;
my $mailCC          = "brandonjs\@somesite.com";
my $mailDomain      = "somesite.com";
my $mailHost        = "mail.somsite.com";
my $mailProg        = "/usr/sbin/sendmail -t -oii";
my $mailTo          = "maillist\@somesite.com";
my $mailSubject     = "$progName";
my $sendEmail       = 0;
my ($mailMsg);
my $userDomain      = domain;
my $userGroup       = group;
my $nasPass         = Password;
my $fileLoc         = somefiler:/vol/vol0/user

# Check if we're on syslog server, if not exit with error.
if (my $hostName=hostname() ne "myhostname") {
    print "ERROR: This script should only be run on myhostname.\n";
    exit 1;
}

# Open the files for reading/writing.
open (PASSWD,"$inputFile") || die ("Can't open $inputFile : $!");
open (UNAMES,"$unameFile") || die ("Can't open $unameFile : $!");
open (ADMINS,"$adminList") || die ("Can't open $adminList : $!");
open (OUTFILE,">$outFile") || die ("Can't open $outFile : $!");
open (ADMINPW,">$adminPasswd") || die ("Can't open $adminPasswd : $!");
open (DECRUFILE,">$decruFile") || die ("Can't open $decruFile : $!");
open (CRONFILE,">$cronFile") || die ("Can't open $cronFile : $!");
open (AHOMEFILE,">>$ahomeFile") || die ("Can't open $ahomeFile : $!");

# Read shell and uid information into a hash.
while (<UNAMES>) {
    chop;
    my ($eMail, $shell, $uid) = split / /;
    $shellHash{$eMail} = $shell;
    $uidHash{$eMail} = $uid;
}
close (UNAMES);

# Sort through hash to find the largest uid, this will be used for any accounts that are not
# in the current file.
$mailMsg = "User accounts added:\n--------------------\n";
$largestUid = 0;
foreach $key (keys(%uidHash)) {
    if ( $uidHash{$key} > $largestUid ) {
        $largestUid = $uidHash{$key};
    }
}
open (UNAMES,">>$unameFile") || die ("Can't open $unameFile : $!");
$largestUid += 1;
print CRONFILE "#!/bin/bash\n";

while ($record = <PASSWD>) {
    open (AHOMEFILERO,"$ahomeFile") || die ("Can't open $ahomeFile : $!");
    @ahome = <AHOMEFILERO>;
    close (AHOMEFILERO);
    ($userName,$eMail,$null,$passWord,$expDate) = split(/:/, $record);
    if ($expDate == "") {
            next;
    }
    ($userName, $null) = split(/@/,$userName);
    $homeDir="/prj/user/$userName";
    $passWord =~ s/^\{(crypt|SHA)\}//i;

    $uid = $uidHash{$eMail};
    $shell = $shellHash{$eMail};
    if (! $shell ) {
            $shell = "/bin/tcsh";
    }
    if (! $uid) {
            $uid = $largestUid;
            $largestUid += 1;
            print UNAMES "$eMail $shell $uid\n";
    }

   $expDate = substr($expDate,0,8);
    if ($expDate > 0) {
        ($year1,$month1,$day1) = Today([$gmt]);
        $year2 = substr($expDate,0,4);
        $month2 = substr($expDate,4,2);
        $day2 = substr($expDate,6,2);
        $dD = Delta_Days($year1, $month1, $day1, $year2, $month2, $day2);
    } else {
        $expDate = Today([$gmt]);
        $dD = 0;
    }

    if ($dD > 0) {
        print CRONFILE "passwd -w 7 -x $dD $userName\n";
        print DECRUFILE "user group grant $userGroup $userName\@$userDomain\n";
    } else {
        print CRONFILE "passwd -w 7 -x 0 $userName\n";
        $shell = "/bin/denylogin";
        print DECRUFILE "user group revoke $userGroup $userName\@$userDomain\n";
    }
    print OUTFILE "$userName:$passWord:$uid:$gid:$eMail:/user/$userName:$shell\n";
    unless(-d $homeDir) {
        mkdir $homeDir;
        chown $uid, $gid, $homeDir;
    }
    unless(`grep $userName $ahomeFile`) {
        print AHOMEFILE "$userName\t\t\t-rw,soft,intr,proto=tcp\t\t$filerLoc/&\n";
        if ($dD > 0) {
            print DECRUFILE "user add --domain $userDomain --id $uid,$gid --password $nasPass nas-user $userName\n";
            print DECRUFILE "user group grant $userGroup $userName\@$userDomain\n";
            $mailMsg .= "\n$userName, $eMail\n";
            $sendEmail = 1;
        }
    }
    if(`grep $userName $adminList`) {
        print ADMINPW "$userName:$passWord:$uid:$gid:$eMail:/user/$userName:$shell\n";
    }
}

close(DECRUFILE);
if ( -s $decruFile )
{
    system("$decruScript --batch $decruFile");
}
unlink($decruFile);
close(OUTFILE);
close(CRONFILE);
close(AHOMEFILE);
chmod(0755, "$cronFile");
close(PASSWD);
close(UNAMES);
close(ADMINS);
close(ADMINPW);
if ($sendEmail) {
    $mailMsg .= "\n\n$userGroup Account information has been propagated.\n Please log into to ensure that the user(s) can log in.\n";
    _mailNotify("$userGroup User account(s) added.", $mailMsg);
}

#
# Sub Routines
#
sub _mailNotify {

    my ($statStr) = shift;
    my ($mailMsg) = shift;

    open(MAIL, "| $mailProg") or warn("WARNING: Unable to open pipe for sendmail: $!\n")
;
    print MAIL <<EndOfMsg;
To: $mailTo
CC: $mailCC
Subject: $mailSubject on $hostName - $statStr

Run Time: $runTime

$mailMsg

Thank You.

EndOfMsg

    close(MAIL) or warn("WARNING: Mail pipe failed: $?\n");
}


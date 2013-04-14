#!/usr/local/bin/perl -w
#==============================================================================|
# $script:  decru_login.pl                                                     |
# $author:  Brandon Schwartz                    		                       |
# $date:    08/08/2007                                                         |
# $purpose: Script to log into the decru machines and grant/deny access to     |
#	    cryptainers or to reboot the machines.	                		       |
#                                                                              |
#==============================================================================|
#
#==============================================================================|
#   Perl modules.                                                              |
#==============================================================================|
use Expect;
use Crypt::Tea;
use Pod::Usage;
use Getopt::Long qw(:config no_ignore_case bundling);
use Config::IniFiles;
use File::Basename;
use File::Copy;
use Carp;
use Sys::Hostname;

#==============================================================================|
# Get command line options and display usage if not given any options or invalid
# options.
#==============================================================================|
my %opts = ();
my %userinfo;
pod2usage(-verbose => 0) 
    unless GetOptions( \%opts, 
            'help|?|h', 
            'man|m', 
            'verbose|v', 
            'reboot|R', 
            'grant|g', 
            'deny|d', 
            'adduser|a', 
            'rmuser|r', 
            'addrack=s' => \$addRackName,
            'rmrack=s' => \$rmRackName,
            'define=s' => \%userinfo, 
            'batch|b=s' => \$batchFile
    );
    foreach (keys %opts) {
             print "$_ = $opts{$_}\n";
     }
pod2usage(-verbose => 1, -msg => "\nExtended Help Section...\n") if ($opts{'help'});
pod2usage(-verbose => 2, -msg => "\nMan pages...\n")             if ($opts{'man'});
pod2usage(-verbose => 1, -msg => "\nYou must provide the --define key=value option...\n")
    if ($opts{'adduser'} && !(%userinfo));
pod2usage(-verbose => 1, -msg => "\nYou must provide the --define key=value option...\n")
    if ($opts{'rmuser'} && !(%userinfo));
pod2usage(-verbose => 1, -msg => "\nYou must not use the --define key=value with this option...\n")
    if(%userinfo && ! ($opts{'adduser'} || $opts{'rmuser'}));
pod2usage(-verbose => 1, -msg => "\nYou must provide a command-line parameter...\n") if (!(%opts) && !($addRackName) && !($rmRackName) && !($batchFile));

# make sure configDir and config file are set.
my $progName = basename($0);
my $configDir = dirname($0);
my $config = Config::IniFiles->new(-file => "$configDir/decru.cfg")
  or _usageStatement("Can't find configuration file: $!\n", $progName);

#==============================================================================|
#   Initialize Vars.                                                           |
#==============================================================================|
my $machines	    = $config->val(General, 'DataForts')    if $config;
$machines =~ s/(\(|\))//g;
my @machines = split(/\|/, $machines);
my $readOnly        = $config->val(Readonly, 'Paths')       if $config;
$readOnly =~ s/(\(|\))//g;
my @readOnlyPaths = split(/\|/, $readOnly);
my $readWrite       = $config->val(Readwrite, 'Paths')      if $config;
$readWrite =~ s/(\(|\))//g;
my @readWritePaths = split(/\|/, $readWrite);
my @listPath 	    = "";
my $machineAdmin    = $config->val(General, 'machineAdmin') if $config;
my $machineAdminPw  = $config->val(General, 'machinePw')    if $config;
my $userAdmin       = $config->val(General, 'userAdmin')    if $config;
my $userAdminPw     = $config->val(General, 'userPw')       if $config;
my $timeout         = 60;
my $ssh;
my $syslogCfDir		= $config->val(General, 'syslogCfDir')	if $config;
my $syslogCfOld		= $config->val(General, 'syslogCfOld')	if $config;
my $syslogCfNew		= $config->val(General, 'syslogCfNew')	if $config;

#==============================================================================|
#   Begin                                                                      |
#==============================================================================|
# Check if we're on syslog server, if not exit with error.
if (my $hostname=hostname() ne "myhostname") {
    print "ERROR: This script should only be run on myhostname.\n";
    exit 1;
}

# Remove root's ssh known_hosts file as it gets in the way.
if (-e "/root/.ssh/known_hosts"){
    unlink("/root/.ssh/known_hosts");
}

##
# Open the file containing the key and encrypted password,
# and set username, password, and decryption key.
if ($opts{'reboot'}) {
	open (FILE, "<$machineAdminPw") || die "Cannot open file, did you remember to run as root?\n";
	$data=<FILE>;
    $admin="$machineAdmin";
    ($key,$password) = split(/\|/,$data);
	close(FILE);
} else {
	open (FILE, "<$userAdminPw") || die "Cannot open file, did you remember to run as root?\n";
	$data=<FILE>;
    $admin="$userAdmin";
    ($key,$password) = split(/\|/,$data);
	close(FILE);
}


# Pack and decrypt the password.
$password = pack("H*",$password);
$password = decrypt($password,$key);

if ($opts{'reboot'}) {
	copy("$syslogCfDir/$syslogCfNew", "$syslogCfDir/$syslogCfOld") or die "File cannot be copied.";	
	system("/etc/init.d/syslog restart");
	# Run through each machine in the list. 
	foreach $host (@machines) {
		$ssh = _getSSHConn($ssh);
		$ssh->send("sys reboot -p\n");
		$ssh->send("quit\n");
		$ssh->expect($timeout,"closed.");
		$ssh->soft_close();
	}

} elsif ($opts{'adduser'}) {
    my (%userObj) = _getUserObj();
    ($host) = @machines;

    $ssh = _getSSHConn($ssh);
	$ssh->send("cli pager off\n");
	$ssh->send("user list\n");
    $ssh->send("quit\n");
    $ssh->expect($timeout,"closed.");
    $ssh->soft_close();
    @listPath = $ssh->before();
    if ((grep (/$userObj{'user'}/, @listPath))) {
        print "ERROR, User already added\n";
        exit 1;
    } 
	if ((grep (/$userObj{'uid'}/, @listPath))) {
	    print "ERROR, Uid already exists, but username is different.  Remove existing user first.\n";
        exit 1;
	} 

    $ssh = _getSSHConn($ssh);
    $ssh->send("user add --domain $userDomain --id $userObj{'uid'},$userObj{'gid'} --password hurry^10 nas-user $userObj{'user'}\n");
    $ssh->send("user group grant $userObj{'group'} $userObj{'user'}\@$userDomain\n");
	$ssh->send("quit\n");
	$ssh->expect($timeout,"closed.");
    $ssh->soft_close();

} elsif ($opts{'rmuser'}) {
    my (%userObj) = _getUserObj();
    ($host) = @machines;
    $ssh = _getSSHConn($ssh);
    $ssh->send("user group revoke $userObj{'group'} $userObj{'user'}\@$userDomain\n");
    $ssh->send("user remove --id $userObj{'uid'} $userObj{'user'}\n");
	$ssh->send("quit\n");
	$ssh->expect($timeout,"closed.");
    $ssh->soft_close();

} elsif ($addRackName) {
    ($host) = @machines;
    my $rackRange = $config->val(Racks, $addRackName)    if $config;
    $rackRange =~ s/(\(|\))//g;
	if (!($rackRange)) {
        print "Rack Range for rack $addRackName is not in $configDir/decru.cfg file.\n";
        print "Please add values for this rack into the config file.\n";
        exit 1;
    }
    $ssh = _getSSHConn($ssh);
    foreach my $path (@readOnlyPaths) {
        $ssh->send("cryptainer ip grant read $path $rackRange\n");
    }
    foreach my $path (@readWritePaths) {
        $ssh->send("cryptainer ip grant access $path $rackRange\n");
    }
    $ssh->send("quit\n");
    $ssh->expect($timeout,"closed.");
    $ssh->soft_close();

} elsif ($rmRackName) {
    ($host) = @machines;
    my $rackRange = $config->val(Racks, $rmRackName)    if $config;
    $rackRange =~ s/(\(|\))//g;
	if (!($rackRange)) {
        print "Rack Range for rack $rmRackName is not in $configDir/decru.cfg file.\n";
        print "Please add values for this rack into the config file.\n";
        exit 1;
    }
    $ssh = _getSSHConn($ssh);
    foreach my $path (@readOnlyPaths) {
	    $ssh->send("cryptainer ip revoke access $path $rackRange\n");
    }
    foreach my $path (@readWritePaths) {
	    $ssh->send("cryptainer ip revoke access $path $rackRange\n");
    }
	$ssh->send("quit\n");
	$ssh->expect($timeout,"closed.");
    $ssh->soft_close();

} elsif ($opts{'grant'} || $opts{'deny'}) {
    ($host) = @machines;
    my $rackRange = $config->val(Racks, 'all')    if $config;
    $rackRange =~ s/(\(|\))//g;
    my @allRackRanges = split(/\|/, $rackRange);
    $ssh = _getSSHConn($ssh);
    foreach my $path (@readOnlyPaths) {
	    if ($opts{'grant'}) {
	        $ssh->send_slow(0,"cryptainer grant read $path $userGroup\@$userDomain\n");
            	foreach my $ipRange (@allRackRanges) {
	            $ssh->send_slow(0,"cryptainer ip grant read $path $ipRange\n");
            	}
	    } else {
		    $ssh->send_slow(0,"cryptainer revoke access,change-perms $path $userGroup\@$userDomain\n");
            	foreach my $ipRange (@allRackRanges) {
	            $ssh->send_slow(0,"cryptainer ip revoke access $path $ipRange\n");
            	}
	    }
    }
    foreach my $path (@readWritePaths) {
	    if ($opts{'grant'}) {
		    $ssh->send_slow(0,"cryptainer grant access $path $userGroup\@$userDomain\n");
            	foreach my $ipRange (@allRackRanges) {
	            $ssh->send_slow(0,"cryptainer ip grant access $path $ipRange\n");
            	}
	    } else {
		    $ssh->send_slow(0,"cryptainer revoke access,change-perms $path $userGroup\@$userDomain\n");
            	foreach my $ipRange (@allRackRanges) {
	            $ssh->send_slow(0,"cryptainer ip revoke access $path $ipRange\n");
            	}
	    }
    }
    $ssh->send("quit\n");
    $ssh->expect($timeout,"closed.");
    $ssh->soft_close();

	$ssh = _getSSHConn($ssh);
	$ssh->send("cli pager off\n");
	if ($opts{'grant'}) {
		$ssh->send("cryptainer acl list\n");
		$ssh->send("quit\n");
		$ssh->expect($timeout,"closed.");
		$ssh->soft_close();
		@listPath = $ssh->before();
		if (!(grep (/$userGroup/, @listPath))) {
			print "ERROR, $userGroup not granted ACLs\n";
		} 
	} else {
		$ssh->send("cryptainer acl list\n");
		$ssh->send("quit\n");
		$ssh->expect($timeout,"closed.");
		$ssh->soft_close();
		@listPath = $ssh->before();
		if (grep (/$userGroup/, @listPath)) {
			print "ERROR, $userGroup ACLs not removed.\n";
		}
	}
} elsif($batchFile) {
	open (BATCHFILE, "<$batchFile") || die "Cannot open batch file for processing.\n";
    my @commandList = <BATCHFILE>;
    close(BATCHFILE);
    ($host) = @machines;
    $ssh = _getSSHConn($ssh);
    $ssh->send("cli pager off\n");
    $ssh->send_slow(0,@commandList);
    $ssh->send("quit\n");
    $ssh->expect($timeout,"closed.");
    $ssh->soft_close();
} else {
    print "Options fell through for some reason.  You shouldn't be able to land here.\n";
    exit 1;
}
exit 0;

#==============================================================================|
# Sub Routines
#==============================================================================|
sub _getUserObj {
    my ($user, $uid, $gid, $group);
    if (%userinfo and (keys %userinfo == 4)) {
        foreach my $keys (sort keys %userinfo) {
            if ($keys =~ /(username|group|uid|gid)/i) {
                if ($keys eq 'username') {
                    $user = $userinfo{$keys};
                }
                if ($keys eq 'uid') {
                    $uid = $userinfo{$keys};
                }
                if ($keys eq 'gid') {
                    $gid = $userinfo{$keys};
                }
                if ($keys eq 'group') {
                    $group = $userinfo{$keys};
                }
                ##
                # create host object.
                %userObj = (
                    'user'      => $user,
                    'uid'       => $uid,
                    'gid'       => $gid,
                    'group'     => $group,
                );
            }
            else {
                croak("\nERROR: Unrecongized key $keys in define statement...");
            }
        }
    } 
    else {
        pod2usage(-verbose => 1, -msg => "\nERROR: Unable to determine key=value pairs or insufficient # of keys needed: 4...\n\n");
    }
    ##
    # return the hash if defined.
    return (%userObj) if (%userObj);

    return;
}

sub _getSSHConn {
    my $ssh = @_;
	$ssh = Expect->spawn("ssh -x $host -l $admin");
	$ssh->debug(0);
    $ssh->expect($timeout,
        [ qr/.yes.no/ =>
            sub {
                my $ssh = shift;
                $ssh->send("yes\n");
                exp_continue;
            }
        ],
        [ qr/password:/ => 
            sub {
                my $ssh = shift;
                $ssh->send("$password\n");
            } 
        ],
        [ timeout => sub {
            die "Never got password prompt on $host, " . $ssh->exp_error()."\n"
            }
        ],
    );
    $ssh->clear_accum();
	$ssh->expect($timeout,'>') || die "No Prompt on $host, " . $ssh->exp_error() . "\n";
    return $ssh;
}


__END__

#==============================================================================|
#   POD documentation                                                          |
#==============================================================================|

=head1 NAME

B<decru_login.pl>

=head1 SYNOPSIS

B<decru_login.pl> I<[ [ --help | -h ] | --man (extended help) ]> I<[ [ --reboot | -R ]> I<[ --grant | -g ]> I<[ --deny | -d ]> I<[ --adduser | -a ]> I<[ --rmuser | -r ]> I<[ --define uid|gid|user|group]>

=head1 DESCRIPTION

The decru_login script is meant to log into the decru machines in order to change ACL's for groups, add or remove users from the allowed user lists,  or to reboot the machines in the event that is needed.
This script requires the following perl modules be installed into your perl distribution:

=over 3

=item Expect;

=item Crypt::Tea;

=item Pod::Usage;

=item Getopt::Long;

=item Config::IniFiles;

=back 

=head1 OPTIONS

=head2 The following options are supported:

=over 3

=item B<[ --reboot | -R ]> 

Provide this option to reboot the Decru machines.

=item B<[ --grant | -g ]> 

Provide this option to grant access to the decru cryptainers as specified in the inifile.

=item B<[ --deny | -d ]>

Provide this option to remove access to the decru cryptainers as specified in the inifile.

=item B<[ --adduser | -a ]>

Provide this option to give a user access to the Decru cryptainers. Must be used in conjuction with the --define options for uid, gid, groupname, and username.

=item B<[ --rmuser | -r ]>

Provide this option to remove a user's access to the Decru cryptainers. Must be used in conjuction with the --define options for uid, gid, groupname, and username.

=item B<[ --addrack ]>

Use this option to give a rack of machines access to the DataFort Acls.

=item B<[ --rmrack ]>

Use this option to remove a rack of machines from access to the DataFort Acls.

=item B<[ --define ]>

Use this item in conjuction with adduser or rmuser to specify the uid, gid, groupname, and username of the user you wish to add or remove from the Decru system.

Valid keys for the define statment are:
    --define uid=UNIX UID of user
    --define gid=UNIX primary GID
    --define username=UNIX username
    --define group=[]

=item B<[ --man | -m ]>

Provide this option to print the entire perl documentation.

=back

=head1 BUGS

B<NONE KNOWN AT THIS TIME>

=head1 NOTES

Note that this script will read in the encrypted password and salt used to create that encryption and proceed to decrypt it.  To change the password or encryption you will need to change the file specified by the script using a perl script which utilizes the Crypt::Tea perl module.  Here's an example script on how to do this:

	#!/usr/local/bin/perl
	use Crypt::Tea;
        my $password = "mypassword";
        my $key = "mykey";

        $password = encrypt($password,$key);
        $password = unpack("H*",$password);

Obviously it would be better to have it read in the password on the command line with noecho turned on so you don't have the password sitting around in a script somewhere.

=head1 EXAMPLES

To reboot the decru machines use:

C<$ ./decru_login.pl --reboot>

Use this to grant access for SEC to the specified (by the inifile) areas on the filers. (Note: This has to already be setup as a cryptainer)

C<$ ./decru_login.pl --grant>

Use this to add a user to the Decru system and add them to the specified group.
C<$ ./decru_login.pl --adduser --define uid=myuid --define gid=mygid --define username=myusername --define group=mygroupname>

=over 3

=back

=head1 SEE ALSO

=head1 AUTHOR

Brandon J. Schwartz

=head1 COPYRIGHT

This script is free software; you can redistribute it and/or modify it under the same terms as Perl itself, either Perl version 5.8.8 or, at your option, any later version of Perl 5 you may have available.

=cut


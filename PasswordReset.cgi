#!/usr/bin/perl -w
# Created by David R. Moore - 2011-04-15
# Modifications made by jmorgan  - 20120529
use strict;
use Net::LDAP;
use CGI;
use Crypt::Cracklib;

my $port = $ENV{'SERVER_PORT'};
my $client = $ENV{'REMOTE_ADDR'};
my $properties = '/etc/PasswordReset/pr.properties';
my($TODAY,$TIMESTAMP,$deny,$app,$search_uid,$ticket,$dn,$uid,$email,$crypt_passwd,$ustring,$custring,$newpw_a,$newpw_b);
my($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
$mon += 1;
$year += 1900;
if($mon <= 9){ $mon = "0$mon"; }
if($mday <= 9){ $mday = "0$mday"; }
if($hour <= 9){ $hour = "0$hour"; }
if($min <= 9){ $min = "0$min"; }
if($sec <= 9){ $sec = "0$sec"; }
$TODAY = "$year-$mon-$mday"; 
$TIMESTAMP = "$hour:$min:$sec";

my %PROP = &get_props($properties);
my $bind = $PROP{bind};
my $log = $PROP{log};
my $logfile = $PROP{logfile};
    $logfile = "$logfile.$TODAY";
my $pwadmin_pass = $PROP{pwadmin_pass};
my $base = $PROP{base};
my $salt = $PROP{salt};
my $dictionary = $PROP{dictionary};
my $webaddress = $PROP{webaddress}; 
my $logo = $PROP{logo};
my $url = $PROP{app_url};
my $app_title = $PROP{app_title};
my $mot = $PROP{app_mot};
my $ssl = $PROP{ssl};
if(($ssl eq '1') || ($ssl =~ m/true/i) || ($ssl =~ m/on/i)){
    $app = "https://$webaddress/$url";
    if($port ne '443'){
        $deny = '1';
    }
}else{ 
    $app = "http://$webaddress/$url";
}
my $exclude_users = $PROP{exclude_users};
my $q = CGI->new;
$search_uid = $q->param('UID');
$ticket = $q->param('TICKET');
$newpw_a = $q->param('NEWPW');
$newpw_b = $q->param('NEWPW_CONFIRM');

my $ldap = Net::LDAP->new( 'ldap.server' ) or die "$@";

print $q->header;
print $q->start_html("$app_title"),
    $q->img({-src=>"http://$webaddress/images/$logo",-align=>'TOP'}),
    $q->h1("$app_title");
&app_notes();

$ldap->bind( "$bind", password => "$pwadmin_pass" );

if((!$q->param) && (!$deny)){
    print $q->start_form(-action => "$app"),
    "Username or Email Address: ", $q->textfield('UID'),
    $q->submit(-name=>'Request Reset'),
    $q->end_form;
}elsif(($q->param) && (!$deny)){
    no warnings 'uninitialized';
    if((!$ticket) && ($search_uid) && (!$newpw_a) && (!$newpw_b)){   
        if($exclude_users =~ m/$search_uid/){
                print "You cannot reset the password for $search_uid, but nice try!\n";
                if($log =~ m/^on$/i){
                    &logit($logfile,"$TODAY","$TIMESTAMP",$search_uid,$client,'FAIL (EXCLUDED)');
                }
                exit;
        }else{
            if(&ldap_uid_search($search_uid,$ldap)){
                my $RET = &ldap_uid_search($search_uid,$ldap);
                ($dn,$uid,$email,$crypt_passwd) = split(/\|/, $RET);
                if($uid){
                    $crypt_passwd =~ s/\{crypt\}//;
                    $ustring = "$TODAY$uid$email$crypt_passwd";
	                $custring = crypt($ustring,$salt);
                    &reply($app,$email,$uid,$custring);    
	                print "An Email has been sent to the address owned by $uid.\n", $q->br;
                }else{
                    #print "$search_uid ?? $exclude_users\n";
                    print "Account not found!\n<br />\n";
                    print "<a href=\"$app\">Try Again?</a>\n<br />";
                    exit;
                }
            }else{
                print "LDAP Search Issue(s). (1)\n";
                exit 1;
            }
        }
    }elsif(($ticket) && ($search_uid) && (!$newpw_a) && (!$newpw_b)){
	    print $q->start_form(-action => "$app"),
            $q->hidden(-name=>'TICKET', -default=>"$ticket"),
            $q->hidden(-name=>'UID', -default=>"$uid"),
            "NEW PASSWORD: ", $q->password_field('NEWPW'), $q->br,
            "CONFIRM PASSWORD: ", $q->password_field('NEWPW_CONFIRM'), $q->br,
            $q->submit(-name=>'COMMIT'),
            $q->end_form; 
    }elsif(($ticket) && ($search_uid) && ($newpw_a) && ($newpw_b)){
        if($newpw_a ne $newpw_b){
            print "Your Password fields did not match, <a href=\"Javascript:window.history.back()\">try again</a>.<br />\n";
            exit;
        }else{
            if(fascist_check($newpw_a,$dictionary) ne 'ok'){
                print $q->p("Password chosen is a dictionary word or its too easy to guess, <a href=\"Javascript:window.history.back()\">try again</a>.<br />\n");
            }else{
                if(&ldap_uid_search($search_uid,$ldap)){
                    my $RET = &ldap_uid_search($search_uid,$ldap);
                    ($dn,$uid,$email,$crypt_passwd) = split(/\|/, $RET);
                    $crypt_passwd =~ s/\{crypt\}//;
                    $ustring = "$TODAY$uid$email$crypt_passwd";
                    $custring = crypt($ustring,$salt);
                    if($ticket eq $custring){    
                        my $STAT = &ldap_passwd_change($search_uid,$newpw_a,$salt,$dn,$ldap);            
   	                    if($STAT eq 'OK'){
                            print "PASSWORD HAS BEEN RESET.\n<br />";
                            if($log =~ m/^on$/i){	
                                &logit($logfile,"$TODAY","$TIMESTAMP",$search_uid,$client,'SUCCESS');
                            }
                        }else{
                            print "PASSWORD COULD NOT BE RESET. ($STAT)\n<br />";
                        }
                    }else{
                        print "$hour: HAH! nice try but you're attempt to reset a password did not work!\n";
                        if($log =~ m/^on$/i){
                            &logit($logfile,"$TODAY","$TIMESTAMP",$search_uid,$client,'FAIL (BAD TICKET)');
                        }
                        exit;
                    }
                }else{
                    print "LDAP Search Issue(s). (2)\n";
                }
            }
        }
    }
}else{
    print <<eoj;
    <b>PLEASE USE HTTPS</b>
    <script type="text/javascript">
        <!--
            window.location = "$app"
        //-->
    </script>
eoj
}


$ldap->unbind;
#print "UserID: $uid\nEmail: $email\nPassword: $crypt_passwd\n";
#print "$uid$email$crypt_passwd";

print $q->p($mot),
    $q->end_html; 

sub ldap_uid_search($$)
{
 my($search_uid,$ldap) = @_;
 my $search = $ldap->search( base => "$base", filter => "(|(uid=$search_uid)(mail=$search_uid))" );
    $search->code && die $search->error;

 foreach my $entry ($search->entries){
    $uid = $entry->get_value('uid');
    $email = $entry->get_value('mail');
    $crypt_passwd = $entry->get_value('userPassword');
    $dn = $entry->dn();
 }
 my $RETURN = "$dn|$uid|$email|$crypt_passwd";
 return $RETURN; 
}

sub ldap_passwd_change($$$$$)
{
 my($search_uid,$newpw_a,$salt,$dn,$ldap) = @_;
 my $STAT;
 my $crypt_pass = crypt($newpw_a,$salt);
 my $crypt_pass_string = "\{crypt\}$crypt_pass";
 my $change = $ldap->modify( $dn,
    changes => [ replace => [ userPassword => "$crypt_pass_string"] ]
  );
 if($change){
    $STAT = 'OK';
 }else{
    $STAT = 'FAIL';
 }
 return $STAT;   
}

sub reply($$$$)
{
   my $MAILCMD = '/bin/mail -s';
   my($app,$email,$uid,$custring) = @_;
   my $MAILMSG = "To Reset you LDAP Password, follow this link: $app?UID=$uid&TICKET=$custring\n";
   my $MAILSUB = "Account: $uid";
   system("/bin/echo \"$MAILMSG\" |$MAILCMD \"$MAILSUB\" $email");
}

sub get_props($)
{
 my %PROP;
 my $properties = shift;

 open(PROP, "<$properties") or die $!;
 while(<PROP>) {
    if(($_ =~ m/^#/) || ($_ =~ m/^\s*$/)){
        next;
    }else{
        my @bA = split(/=/, $_);
        if(scalar(@bA) > 2){
            my $k = shift(@bA);
            my $v = join('=', @bA);
            $PROP{$k}=$v;
        }else{
            $PROP{$1}=$2 while m/(\S+)=(.*)/g;
        }
    }
 }
 close(PROP);
 return %PROP;
}

sub logit()
{
my($logfile,$TODAY,$TIMESTAMP,$uid,$client,$msg) = @_;
open(LOG, ">>$logfile") or die "Cannot open $logfile $!\n";
    print LOG "$TODAY $TIMESTAMP CHANGE $msg: $uid by $client\n";
close(LOG);
}

sub app_notes()
{
    print <<eot;
 \n
 <!-- LDAP_passwordReset Written by ---------------------------  2011-04-15 -->
 \n
eot
}

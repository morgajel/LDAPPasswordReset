#!/usr/bin/perl -wT
# Created by David R. Moore - 2011-04-15
# Modifications made by jmorgan  - 20120529
# Refactored by jmorgan - 20130321
use strict;
use CGI;
use Config::IniFiles;
use Crypt::Cracklib;
use Data::Dumper;
use MIME::Base64;
use MIME::Lite;
use Net::LDAP;
use POSIX qw( strftime );
use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash);
use Crypt::Random;
$ENV{PATH}="";

# Load our lovely configuration file
my $mainconfig = Config::IniFiles->new( -file => '/etc/PasswordReset/properties.ini' );

# Configure Logging
my $logfile = $mainconfig->val('main','logfile');
if ($mainconfig->val('main','datestamp_log')){
    my $date =  strftime "%F", localtime;
    $logfile.="$date";
}


# Redirect if we want to guarantee SSL and it's not SSL.
if ( defined $mainconfig->val('main','ssl') and $mainconfig->val('main','ssl_enabled') eq "true" and $ENV{'SERVER_PORT'}  ne '443'  ) {
    print print_redirect($mainconfig);
    exit;
}

# Our super awesome CGI object.
my $q         = CGI->new;
my $params= sanitize_inputs($q);



#Instnatiate our LDAP connection
my $ldap = Net::LDAP->new( $mainconfig->val('main','ldap_host')) or die "$@";
#FIXME set up proper credentials.
$ldap->bind( $mainconfig->val('main','binddn')  , password => $mainconfig->val('main','bind_pass') ) or die "couldn't connect to LDAP!";
#$ldap->bind ;


#Start collecting our lovely page into the $content variable which we print out at the end.
my $content= print_header($mainconfig);

################################################################
# Now onto the crux of the application


# If no parameters exist, we presume that this is the default screen- the search form.
if ($params->{'action'} eq 'default'){
    $content.=print_search_form();

# If "Request Reset" is submitted, Then we know to start the process and examine their search term.
# If we find their search term, we begin the reset process.
} elsif ( $params->{'action'} eq 'Request Reset') {
    #search for user, make sure they're not in excluded and send ticket.
    my $user= ldap_search($mainconfig,$ldap, $params->{'searchterm'}   ) ;
    if (! defined $user){
        # spit out "not found" error
        $content.="<div>User not found. Care to try again?</div>";
        $content.=print_search_form();

    }elsif ( grep { /$user->get_value('uid')/ }   split(',',$mainconfig->val('main','excluded_users') )  ){
        # This returns if you're trying to reset an excluded user
            $content.= "<pre>You cannot reset the password for ".$params->{'searchterm'}.", but nice try!</pre>";
        $content.=print_search_form();

    }else {
        # User found and allowed.
        $content.="An Email has been sent to the address owned by ".$user->get_value('uid').".\n",
        send_email($mainconfig,$user);

        #create token and send email
    }
sub send_email{
    my ($mainconfig,$user)=@_;
    my $token=encode_base64(create_token($user));
    my $uid=encode_base64($user->get_value('uid'));
    my $url=$mainconfig->val('main','url')."?Confirm=true&uid=$uid&token=$token";

    
    if ( $user->get_value('mail') =~/^([a-z0-9\.@-_]{3,})$/){
        my $email=$1;
        my $msg = MIME::Lite->new(
                From    => $mainconfig->val('main','replyaddress'),
                To      => $user->get_value('mail'),
                Subject => 'Password reset for '.$mainconfig->val('main','title'),
                Type    =>'multipart/related',
                Data    => $content
            );
        $msg->attach(
            Type => 'text/html',
            Data => qq{
                <body>
                    Here is your <a href="$url">password reset link</a>. If you did not request it, you can ignore it.
                </body>
            },
        );



        $msg->send;
    }
}



# If "Confirm Account" is submitted, The user has clicked the link in the email.
# We should verify their ticket and present them with the actual password reset form.
} elsif ( $params->{'action'} eq 'Confirm') {


# If "Change Password" is submitted, The user has submitted their new password.
# We need to re-verify their ticket, confirm the passwords match, and that cracklib approves
# otherwise redisplay the reset form.
} elsif ( $params->{'action'} eq 'Change Password') {


#ORIGINAL CODE
#    if ( ( !$ticket ) && ($search_uid) && ( !$newpw_a ) && ( !$newpw_b ) ) {
#        }
#        else {
#                my $RET = &ldap_uid_search( $search_uid, $ldap );
#                ( $dn, $uid, $email, $crypt_passwd ) = split( /\|/, $RET );
#                if ($uid) {
#                    $crypt_passwd =~ s/\{crypt\}//;
#                    $ustring = "$TODAY$uid$email$crypt_passwd";
#                    $custring = crypt( $ustring, $salt );
#                    &reply( $app, $email, $uid, $custring );
#                    print
#                      "An Email has been sent to the address owned by $uid.\n",
#                      $q->br;
#                }
#                else {
#
#                    #print "$search_uid ?? $exclude_users\n";
#                    print "Account not found!\n<br />\n";
#                    print "<a href=\"$app\">Try Again?</a>\n<br />";
#                    exit;
#                }
#            }
#            else {
#                print "LDAP Search Issue(s). (1)\n";
#                exit 1;
#            }
#        }
#    }
#    elsif ( ($ticket) && ($search_uid) && ( !$newpw_a ) && ( !$newpw_b ) ) {
#        print $q->start_form( -action => "$app" ),
#          $q->hidden( -name => 'TICKET', -default => "$ticket" ),
#          $q->hidden( -name => 'UID',    -default => "$uid" ),
#          "NEW PASSWORD: ",     $q->password_field('NEWPW'),         $q->br,
#          "CONFIRM PASSWORD: ", $q->password_field('NEWPW_CONFIRM'), $q->br,
#          $q->submit( -name => 'COMMIT' ),
#          $q->end_form;
#    }
#    elsif ( ($ticket) && ($search_uid) && ($newpw_a) && ($newpw_b) ) {
#        if ( $newpw_a ne $newpw_b ) {
#            print "Your Password fields did not match, <a href=\"Javascript:window.history.back()\">try again</a>.<br />\n";
#            exit;
#        }
#        else {
#            if ( fascist_check( $newpw_a, $dictionary ) ne 'ok' ) {
#                print $q->p( "Password chosen is a dictionary word or its too easy to guess, <a href=\"Javascript:window.history.back()\">try again</a>.<br />\n"
#                );
#            }
#            else {
#                if ( &ldap_uid_search( $search_uid, $ldap ) ) {
#                    my $RET = &ldap_uid_search( $search_uid, $ldap );
#                    ( $dn, $uid, $email, $crypt_passwd ) = split( /\|/, $RET );
#                    $crypt_passwd =~ s/\{crypt\}//;
#                    $ustring = "$TODAY$uid$email$crypt_passwd";
#                    $custring = crypt( $ustring, $salt );
#                    if ( $ticket eq $custring ) {
#                        my $STAT =
#                          &ldap_passwd_change( $search_uid, $newpw_a, $salt,
#                            $dn, $ldap );
#                        if ( $STAT eq 'OK' ) {
#                            print "PASSWORD HAS BEEN RESET.\n<br />";
#                            if ( $log =~ m/^on$/i ) {
#                                &logit( $logfile, "$TODAY", "$TIMESTAMP",
#                                    $search_uid, $client, 'SUCCESS' );
#                            }
#                        }
#                        else {
#                            print
#                              "PASSWORD COULD NOT BE RESET. ($STAT)\n<br />";
#                        }
#                    }
#                    else {
#                        print
#"$hour: HAH! nice try but you're attempt to reset a password did not work!\n";
#                        if ( $log =~ m/^on$/i ) {
#                            &logit( $logfile, "$TODAY", "$TIMESTAMP",
#                                $search_uid, $client, 'FAIL (BAD TICKET)' );
#                        }
#                        exit;
#                    }
#                }
#                else {
#                    print "LDAP Search Issue(s). (2)\n";
#                }
#            }
#        }
#    }
#}
#else {
}

$ldap->unbind;
print $content;
print  $q->end_html;
exit;


###################################################################
###################################################################
###################################################################
###################################################################
# Subroutines go under here.


# ORIGINAL CODE
#sub ldap_passwd_change($$$$$) {
#    my ( $search_uid, $newpw_a, $salt, $dn, $ldap ) = @_;
#    my $STAT;
#    my $crypt_pass = crypt( $newpw_a, $salt );
#    my $crypt_pass_string = "\{crypt\}$crypt_pass";
#    my $change =
#      $ldap->modify( $dn,
#        changes => [ replace => [ userPassword => "$crypt_pass_string" ] ] );
#    if ($change) {
#        $STAT = 'OK';
#    }
#    else {
#        $STAT = 'FAIL';
#    }
#    return $STAT;
#}
#

#################################
# Clean Implementation Functions

sub print_header {
    my ($config)=@_;
    my $content;
    $content.= $q->header;
    # FIXME Would thse be better served as a heredoc?
    $content.=$q->start_html($config->val('main','title'));
    $content.="<img src='".$config->val('main','logo')."' style='vertical-align:top' >";
    $content.="<h1>".$config->val('main','title')."</h1>";
    return $content;
}

sub print_search_form   {
    my $content;
    #TODO could this be templated?
    $content.= $q->start_form( -action =>  );
    $content.= "Username or Email Address: ";
    $content.= $q->textfield('searchterm');
    $content.= $q->submit( -name => 'Request Reset' );
    $content.= $q->end_form;
    return $content;
}

sub ldap_search {
    my ($config,$ldap, $searchterm ) = @_;

    my $search = $ldap->search(
        'base'   => $config->val('main','base_dn'),
        'filter' => "(|(uid=$searchterm)(mail=$searchterm))"
    );
    $search->code && die $search->error;

    return $search->entry();
}
sub print_redirect {
    my ($config)=@_;
    my $app = "https://" .$config->val('main','url') ;
    print <<eoj;
    <html><body>
    <b>PLEASE USE HTTPS</b>
    <script type="text/javascript">
        <!--
            window.location = "$app"
        //-->
    </script>
    </body></html>
eoj
}
sub salt {
    my $octet=Crypt::Random::makerandom_octet(Length=>16);
    return $octet;
}

sub create_token{
    my ($user)=@_;
    my $date =  strftime "%F", localtime;
    my $prehash=$date.$user->get_value('uid').$user->get_value('mail').$user->get_value('userPassword');
        my $salt=salt();
        my $token= bcrypt_hash({
                        key_nul => 1,
                        cost => 8,
                        salt => $salt,
                    }, $prehash);
    return $token;
}
sub sanitize_inputs {
    my ($q)=@_;
    my $params={};
    if (defined $q->param('Request Reset')){
        $params->{'action'}='Request Reset';
    } elsif (defined $q->param('Confirm')){
        $params->{'action'}='Confirm';
    } elsif (defined $q->param('Change Password')){
        $params->{'action'}='Change Password';
    }else{
        $params->{'action'}='default';
    }
    if (defined $q->param('uid') and $q->param('uid')=~/^([a-z0-9\.]{3,})$/){
        $params->{'uid'}=$1;
    }
    if (defined $q->param('token') and $q->param('token')=~/^([a-z0-9]{8,})$/){
        $params->{'token'}=$1;
    }
    if (defined $q->param('searchterm') and $q->param('searchterm')=~/^([a-z0-9\.@-_]{3,})$/){
        $params->{'searchterm'}=$1;
    }
    return $params;
}



#!/usr/bin/perl -wT
# Created by David R. Moore - 2011-04-15
# Modifications made by jmorgan  - 20120529
# Refactored by jmorgan - 20130321
###############################################################################

=head1 NAME

    PasswordReset.cgi - A simple LDAP password reset utility

=head1 USAGE

    Drop it into cgi-bin, deploy the config to /etc/PasswordReset/properties.ini and configure.

=head1 DESCRIPTION

    Ever get tired of users asking for their password to be reset? This utility 
    implements a modern "tokenized password reset link" pattern to reset their
    password from the email address they have on file.

=cut

###############################################################################


use strict;
use warnings;
use CGI;
use Carp;
use Config::IniFiles;
use Crypt::Cracklib;
use Crypt::Eksblowfish::Bcrypt qw(en_base64 de_base64);
use Crypt::Random;
use Data::Dumper;
use Digest::Bcrypt;
use MIME::Lite;
use Net::LDAP;
use Net::LDAP::Extension::SetPassword;
use POSIX qw( strftime );
use Switch 'Perl5', 'Perl6';

# Lets get the eaint out of our ENV Path. We're not using it anyways...
local $ENV{'PATH'}='/bin';

# Load our lovely configuration file
my $mainconfig = Config::IniFiles->new( -file => '/etc/PasswordReset/properties.ini' );

# Configure Logging
#FIXME: make sure it exists, then implement it!
#FIXME: Actually, you know, log stuff.
my $logfile = $mainconfig->val('main','logfile');
if ($mainconfig->val('main','datestamp_log')){
    my $date =  strftime "%F", localtime;
    $logfile.="$date";
}


# Redirect if we want to guarantee SSL and it's not SSL.
#FIXME is this broke for non-443 ssl?
if ( $mainconfig->val('main','ssl_enabled') eq "true" and $ENV{'SERVER_PORT'}  ne '443'  ) {
    print print_redirect($mainconfig);
    exit;
}


# Our super awesome CGI object. 
my $q         = CGI->new();


#untainted params from CGI.
my $params= sanitize_inputs($q);


#Instanatiate our LDAP connection. Note we rely on a privileged user who can write to the userpassword attrs, so buyer beware.
my $ldap = Net::LDAP->new( $mainconfig->val('main','ldap_host')) or croak $@;
$ldap->bind( $mainconfig->val('main','binddn')  , password => $mainconfig->val('main','bind_pass') ) or croak "couldn't connect to LDAP!";


#Start collecting our lovely page into the $content variable which we print out at the end.
my $content= print_header($mainconfig);

################################################################
# Now onto the crux of the application. The workflow walks down the primary control structure.


# If no parameters exist, we presume that this is the default screen- the search form.
given ($params->{'action'}){
    when('default') {
        $content.=print_search_form();
    } 


    # If "Request Reset" is submitted, Then we know to start the process and examine their search term.
    # If we find their search term, we begin the reset process.
    when('Request Reset') {

        #search for user, make sure they're not in excluded and send token link.
        my $userobj= ldap_search($mainconfig, $ldap, $params->{'searchterm'}   ) ;

        #User was not found...
        if (! defined $userobj){
            $content.="<p class='error'>User '".$params->{'searchterm'}."' not a valid uid or email address. Care to try again?</p>\n";
            $content.=print_search_form();
    
        # This returns if you're trying to reset an excluded user
        }elsif ( grep { m/$userobj->get_value('uid')/xms }   split(/,/xms,$mainconfig->val('main','excluded_users') )  ){
            $content.= "<p class='error'>You cannot reset the password for ".$params->{'searchterm'}.", but nice try!</p>\n";
            $content.=print_search_form();
    
        #User is good, send.
        }else {
            # User found and allowed.
            $content.="<p class='info'>An Email has been sent to the address owned by ".$userobj->get_value('uid').".</p>\n";
            send_email($mainconfig,$userobj);
        }
    }


    # If "Confirm Account" is submitted, The user has clicked the link in the email.
    # We should verify their token and present them with the actual password reset form.
    when ('Confirm') {
        if ( verify_token($mainconfig, $ldap, $params)  ) {
            $content.="<p class='info'>Token Authenticated. Welcome ".$params->{'uid'}.".</p>\n";
            $content.=print_password_form($params);
        }else{
            $content.="<p class='error'>Something was wrong with the token; either it has expired, your password has already changed or there is another issue. Try again?</p>\n";
            $content.=print_search_form();
        }
    }
    # If "Change Password" is submitted, The user has submitted their new password.
    # We need to re-verify their token, confirm the passwords match, and that cracklib approves
    # otherwise redisplay the reset form.
    #TODO confirm password page
    #TODO refactor ldap_search to have less calls
    when ('Change Password') {
        if ( verify_token($mainconfig, $ldap, $params)  ) {
            $content.="<p class='info'>Token Authenticated. Welcome ".$params->{'uid'}.".</p>\n";
            if ($params->{'newpass'} eq $params->{'confirmpass'}){
                if ( check( $params->{'newpass'})  ) {
                    my $user= ldap_search_user($mainconfig, $ldap, $params->{'uid'}   ) ;
    
                    my $mesg = $ldap->set_password(
                      user => $user->dn(),
                      newpasswd => $params->{'newpass'}
                    );
                    if ($mesg->code()){
                        $content.="<p class='error'>Oh Noes, Reset didn't work! ". $mesg->code(). ": ". $mesg->error()  ;
                    }else{
                        $content.="<p class='success'>Your Token is correct, your passwords match, and they're plenty strong- Password Reset!</p>\n";
                    }
    
    
                }else{
                    $content.= "<p class='error'>Your password is either a dictionary word or is too easy to guess according to CrackLib; Please try something a little more secure.</p>\n";
                    $content.=print_password_form($params);
                }
            }else{
                $content.="<p class='error'>Your paswords didn't match... try again?</p>\n";
                $content.=print_password_form($params);
            }
        }else{
            $content.="<p class='error'>Something was wrong with the token; either it has expired, or there is an issue. Try again? </p>\n";
            $content.=print_search_form();
        }
    }
}

$ldap->unbind;
$content.= print_footer($mainconfig);
print $content;
exit;


###################################################################
###################################################################
###################################################################
###################################################################
# Subroutines go under here.



###############################################################################

=head2 print_header()

Return an HTML snippet for the top of the page.

=cut

##############################################################################
sub print_header {
    my ($config)=@_;
    my $css=print_css();
    
    my $subcontent= $q->header;
    my $title= $config->val('main','title');
    my $img=" ";
    if (defined $config->val('main','logo')){
        $img="<img src='".$config->val('main','logo')."' style='vertical-align:top' >";
    }
    # FIXME Would thse be better served as a theredoc?
    $subcontent.=<<"EOF"
<!DOCTYPE html>
<html>
    <head>
        <title>$title</title>
        $css
    <head>
    <body>
        $img
        <h1>$title</h1>
EOF
;
    return $subcontent;
}

###############################################################################

=head2 print_footer()

Return an HTML snippet for the end of the page.

=cut

##############################################################################
sub print_footer {
    my ($config)=@_;
    my $subcontent=$q->end_html;
    return $subcontent;
}

###############################################################################

=head2 print_css()

Return an HTML snippet of inline CSS.

=cut

##############################################################################
sub print_css{
    my $subcontent;

    $subcontent.=<<"EOF" 
            <style type="text/css" >
            .error{ 
                font-weight:bold;
                color:red;
            }
            .success{ 
                font-weight:bold;
                color:green;
            }
            .info{ 
                color:blue;
            }
            </style>
EOF
;
    return $subcontent;
}

###############################################################################

=head2 print_password_form()

Return an HTML snippet of a password reset form.

=cut

##############################################################################
sub print_password_form   {
    my ($parameters)=@_;
    my $subcontent;
    #TODO could this be templated?
    $subcontent.= $q->start_form( -action =>  );
    $subcontent.= "Enter your new password <br>\n";
    $subcontent.= "<label>New Password</label>".$q->password_field('newpass')."<br>\n";
    $subcontent.= "<label>Confirm Password</label>".$q->password_field('confirmpass');
    $subcontent.= $q->hidden(-name=>'uid',     -value=>en_base64($parameters->{'uid'}) );
    $subcontent.= $q->hidden(-name=>'token',   -value=>$parameters->{'token'} );
    $subcontent.= $q->hidden(-name=>'s',       -value=>en_base64($parameters->{'token'} ));
    $subcontent.= $q->submit( -name => 'Change Password' );
    $subcontent.= $q->end_form;
    return $subcontent;
}

###############################################################################

=head2 print_search_form()

Return an HTML snippet of a search form.

=cut

##############################################################################
sub print_search_form   {
    my $subcontent;
    #TODO could this be templated?
    $subcontent.= $q->start_form( -action =>  );
    $subcontent.= "Username or Email Address: ";
    $subcontent.= $q->textfield('searchterm');
    $subcontent.= $q->submit( -name => 'Request Reset' );
    $subcontent.= $q->end_form;
    return $subcontent;
}

###############################################################################

=head2 ldap_search()

Return a user object that matches a given username or email address

=cut

##############################################################################
sub ldap_search {
    my ($config,$ldapobj, $searchterm ) = @_;

    my $search = $ldapobj->search(
        'base'   => $config->val('main','base_dn'),
        'filter' => "(|(uid=$searchterm)(mail=$searchterm))"
    );
    #FIXME this smells, needs refactoring.
    $search->code && croak $search->error;

    #FIXME popping first entry off may be troublesome for users that share an emailaddress 
    # (wtf would that even happen?)
    return $search->entry();
}

###############################################################################

=head2 ldap_search_user()

Return a user object that matches a given username

=cut

##############################################################################
sub ldap_search_user {
    my ($config,$ldapobj, $username ) = @_;
    my $search = $ldapobj->search(
        'base'   => $config->val('main','base_dn'),
        'filter' => "(|(uid=$username))"
    );
    #FIXME this smells, needs refactoring.
    $search->code && croak $search->error;

    return $search->entry();
}

###############################################################################

=head2 print_redirect()

Return small html redirect to get users to https.

=cut

##############################################################################
sub print_redirect {
    my ($config)=@_;
    my $app = "https://" .$config->val('main','url') ;
    return <<"EOF";
    <html><body>
    <b>PLEASE USE HTTPS</b>
    <a href="$app">click here</a>
    <script type="text/javascript">
        <!--
            window.location = "$app"
        //-->
    </script>
    </body></html>
EOF
}

###############################################################################

=head2 send_email()

Send an email to the given user using their email address. Email contains a 
tokenized link that is good until midnight.

=cut

##############################################################################
sub send_email{
    my ($config,$user)=@_;
    my $salt=salt();
    my $token=create_token($user->get_value('uid'),$user->get_value('mail'),$salt,$user->get_value('userPassword'));
    my $uid=en_base64($user->get_value('uid'));
    my $url=$config->val('main','url')."?Confirm=true&uid=$uid&token=$token&s=".en_base64($salt);
    my $name=$user->get_value('givenName');
    if ( $user->get_value('mail') =~m/^([a-z0-9\.@-_]{3,})$/xms){
        my $email=$1;
        my $msg = MIME::Lite->new(
                From    => $config->val('main','replyaddress'),
                To      => $user->get_value('mail'),
                Subject => 'Password reset for '.$config->val('main','title'),
                Type    =>'multipart/related',
            );
        $msg->attach(
            Type => 'text/html',
            Data => <<"EOF"
                <body>
                    Hi $name, here is your <a href="$url">password reset link</a>. If you did not request it, you can ignore it.
                </body>
EOF

            
        );
        $msg->send;
    }
    return 1;
}
sub salt {
    my $octet=Crypt::Random::makerandom_octet(Length=>16);
    return $octet;
}

###############################################################################

=head2 create_token()

Create a token from the date, userid, email address, password and salt.
Token is in hexdigest format.

=cut

##############################################################################
sub create_token{
    my ($uid,$mail,$salt,$pass)=@_;
    my $date =  strftime "%F", localtime;
    my $bcrypt=Digest::Bcrypt->new();
    $bcrypt->add($date);
    $bcrypt->add($uid);
    $bcrypt->add($mail);
    $bcrypt->add($pass);
    $bcrypt->salt($salt);
    $bcrypt->cost("10");
    my $token=$bcrypt->hexdigest;
    return $token;
}

###############################################################################

=head2 verify_token()

Check to see if the user-provided token matches the generated token

=cut

##############################################################################
sub verify_token{
    my($config,$ldapobj,$parameters)=@_;
    my $user= ldap_search_user($config, $ldapobj, $parameters->{'uid'}   ) ;
    my $testtoken=create_token($user->get_value('uid'),$user->get_value('mail'),$parameters->{'salt'},$user->get_value('userPassword'));
    if ($testtoken eq $parameters->{'token'}){
        return 1;
    }else{
        return 0;
    }
    
}
###############################################################################

=head2 sanitize_inputs()

Untaint CGI params and return $params structure

=cut

##############################################################################
sub sanitize_inputs {
    my ($cgi)=@_;
    my $parameters={};
    if (defined $cgi->param('Request Reset')){
        $parameters->{'action'}='Request Reset';
    } elsif (defined $cgi->param('Confirm')){
        $parameters->{'action'}='Confirm';
    } elsif (defined $cgi->param('Change Password')){
        $parameters->{'action'}='Change Password';
    }else{
        $parameters->{'action'}='default';
    }
    if (defined $cgi->param('uid') and de_base64($cgi->param('uid'))=~m/^([a-z0-9\.]{3,})$/xms){
        $parameters->{'uid'}=$1;
    }
    if (defined $cgi->param('s') and ($cgi->param('s')=~m/^([a-zA-Z0-9\+\/\-_\.:!=]*)$/xms)){
        #FIXME should filter decrypted taint as well
        $parameters->{'salt'}=de_base64($1);
    }
    if (defined $cgi->param('token') and $cgi->param('token')=~m/^([a-zA-Z0-9\+\/\-_\.:!=]*)$/xms){
        $parameters->{'token'}=$1;
    }
    if (defined $cgi->param('searchterm') and $cgi->param('searchterm')=~m/^([a-z0-9\.@-_]{1,})$/xms){
        $parameters->{'searchterm'}=$1;
    }

    if (defined $cgi->param('newpass') and $cgi->param('newpass')=~m/^(.*)$/xms){
        #FIXME need better untainting
        $parameters->{'newpass'}=$1;
    }

    if (defined $cgi->param('confirmpass') and $cgi->param('confirmpass')=~m/^(.*)$/xms){
        #FIXME need better untainting
        $parameters->{'confirmpass'}=$1;
    }
    return $parameters;
}

__END__


=head1 AUTHOR

David R. Moore
Jesse Morgan (morgajel)  C<< <morgajel@gmail.com> >>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2011, David R. Moore. All rights reserved.
Copyright (c) 2013, Jesse Morgan (morgajel) C<< <morgajel@gmail.com> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

=cut

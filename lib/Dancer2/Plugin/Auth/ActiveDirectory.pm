package Dancer2::Plugin::Auth::ActiveDirectory;

=head1 NAME

Dancer2::Plugin::Auth::ActiveDirectory - Authentication module for MS ActiveDirectory

=head1 VERSION

Version 0.03

=cut

our $VERSION = '0.03';

use 5.10.0;
use strict;
use warnings FATAL => 'all';
use Dancer2::Plugin;
use Net::LDAP qw[];
use Net::LDAP::Constant qw[LDAP_INVALID_CREDENTIALS];
my $ErrorCodes = {
    '525' => { error => 'user not found' },
    '52e' => { error => 'invalid credentials' },
    '530' => { error => 'not permitted to logon at this time' },
    '531' => { error => 'not permitted to logon at this workstation' },
    '532' => { error => 'password expired' },
    '533' => { error => 'data 533' },
    '701' => { error => 'account expired' },
    '773' => { error => 'user must reset password' },
    '775' => { error => 'user account locked' },
    '534' => {
        error       => 'account disabled',
        description => 'The user has not been granted the requested logon type at this machine'
    },
};

# -----------------------------------------------
# Preloaded methods go here.
# -----------------------------------------------
# Encapsulated class data.

sub _authenticate {
    my ( $dsl, $s_username, $s_auth_password ) = @_;
    my $hr_stg = plugin_setting();
    my $or_connection = Net::LDAP->new( $hr_stg->{host}, port => 389, timeout => 60 );
    unless ( defined $or_connection ) {
        my $host = $hr_stg->{host};
        $dsl->error(qq/Failed to connect to '$host'. Reason: '$@'/);
        return undef;
    }
    my $s_principal = $hr_stg->{principal};
    my $s_user      = sprintf( '%s@%s', $s_username, $s_principal );
    my $message     = $or_connection->bind( $s_user, password => $s_auth_password );
    return _parse_error_message($message) if ( $dsl->_v_is_error( $message, $s_user ) );
    my $s_domain = $hr_stg->{domain};
    my $result   = $or_connection->search(    # perform a search
        base   => qq/dc=$s_principal,dc=$s_domain/,
        filter => qq/(&(objectClass=person)(userPrincipalName=$s_user.$s_domain))/,
    );
    foreach ( $result->entries ) {
        my $groups = [];
        foreach my $group ( $_->get_value(q/memberOf/) ) {
            push( @$groups, $1 ) if ( $group =~ m/^CN=(.*),OU=.*$/ );
        }
        return {
            uid       => $s_username,
            firstname => $_->get_value(q/givenName/),
            surname   => $_->get_value(q/sn/),
            groups    => $groups,
            rights    => _rights_by_user( $hr_stg, $groups ),
            user      => $s_user,
        };
    }
    return undef;
}

sub _authenticate_config {
    return plugin_setting();
}

sub _has_right {
    my ( $dsl, $o_session_user, $s_right_name ) = @_;
    my $hr_rights  = plugin_setting()->{rights};
    my $s_ad_group = $hr_rights->{$s_right_name};
    return grep( /$s_ad_group/, @{ $o_session_user->{groups} } );
}

sub _list_users {
    my ( $dsl, $o_session_user, $search_string ) = @_;
    my $hr_stg = plugin_setting();
    my $or_connection = Net::LDAP->new( $hr_stg->{host}, port => 389, timeout => 60 );
    unless ( defined $or_connection ) {
        my $host = $hr_stg->{host};
        $dsl->error(qq/Failed to connect to '$host'. Reason: '$@'/);
        return undef;
    }
    my $s_user = $o_session_user->{user};
    my $message = $or_connection->bind( $s_user, password => $o_session_user->{password} );

    return undef if ( $dsl->_v_is_error( $message, $s_user ) );
    my $s_principal = $hr_stg->{principal};
    my $s_domain    = $hr_stg->{domain};
    my $result      = $or_connection->search(
        base   => qq/dc=$s_principal,dc=$s_domain/,
        filter => qq/(&(objectClass=person)(name=$search_string*))/,
    );
    my $return_names = [];
    push( @$return_names, { name => $_->get_value(q/name/), uid => $_->get_value(q/sAMAccountName/), } ) foreach ( $result->entries );
    return $return_names;
}

sub _v_is_error {
    my ( $dsl, $message, $s_user ) = @_;
    if ( $message->is_error ) {
        my $error = $message->error;
        my $level = $message->code == LDAP_INVALID_CREDENTIALS ? 'debug' : 'error';
        $dsl->error(qq/Failed to authenticate user '$s_user'. Reason: '$error'/);
        return 1;
    }
    return 0;
}

sub _rights {
    return plugin_setting()->{rights};
}

sub _rights_by_user {
    my ( $hr_stg, $a_user_groups ) = @_;
    my $hr_rights = $hr_stg->{rights};
    return unless $hr_rights;
    my $ret_rights = {};
    foreach ( keys %$hr_rights ) {
        my $s_ad_group = $hr_rights->{$_};
        $ret_rights->{$_} = 1 if ( grep( /$s_ad_group/, @{$a_user_groups} ) );
    }
    return $ret_rights;
}

sub _parse_error_message {
    my ($message)   = @_;
    my ($errorcode) = $message->{errorMessage} =~ m/(?:data\s(.*)),/;
    return $ErrorCodes->{$errorcode};
}

=head1 SYNOPSIS

Configuration:

    plugins:
      Auth::ActiveDirectory:
        host: 0.0.0.0
        principal: yourprincpal
        domain: somedomain
        rights:
          definedright1: ad-group
          definedright2: ad-group
          definedright3: another-ad-group
          definedright4: another-ad-group

Code:

    post '/login' => sub {
        session 'user' => authenticate( params->{user}, params->{pass} );
        return template 'index', { html_error => 'Authentication failed!!' }
            unless ( session('user') );
        return template 'index', { html_error => 'No right for this page!!' }
            if( !has_right( session('user'), 'definedright1') );
        template 'index', { loggedin => 1 };
    };

=head1 SUBROUTINES/METHODS

=head2 authenticate

Basicaly the subroutine for authentication in the ActiveDirectory

=cut

register authenticate => \&_authenticate;

=head2 authenticate_config

Subroutine to get configuration for ActiveDirectory

=cut

register authenticate_config => \&_authenticate_config;

=head2 has_right

Check if loged in user has one of the configured rights

=cut

register has_right => \&_has_right;

=head2 list_users

=cut

register list_users => \&_list_users;

=head2 rights

Subroutine to get configurated rights

=cut

register rights => \&_rights;

=head2 for_versions

=cut

register_plugin for_versions => [2];

1;    # Dancer2::Plugin::Auth::ActiveDirectory

__END__

=head1 AUTHOR

Mario Zieschang, C<< <mziescha at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-Dancer2-Plugin-Auth-ActiveDirectory at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Dancer2-Plugin-Auth-ActiveDirectory>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 MOTIVATION

If you have a run in programming you don't always notice all packages in this moment.
And later when someone will know which packages are used, it's not neccessary to look at all of the packages.

Usefull for the Makefile.PL or Build.PL.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Dancer2::Plugin::Auth::ActiveDirectory


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Dancer2-Plugin-Auth-ActiveDirectory>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Dancer2-Plugin-Auth-ActiveDirectory>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Dancer2-Plugin-Auth-ActiveDirectory>

=item * Search CPAN

L<http://search.cpan.org/dist/Dancer2-Plugin-Auth-ActiveDirectory/>

=back

=head1 ACKNOWLEDGEMENTS

=head1 LICENSE AND COPYRIGHT

Copyright 2015 Mario Zieschang.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=cut

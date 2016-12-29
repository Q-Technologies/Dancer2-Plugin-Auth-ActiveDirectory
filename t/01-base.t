#!perl -T
use strict;
use warnings;
use Plack::Test;
use Test::More import => ['!pass'];
use HTTP::Request::Common qw(GET POST);
use lib '.';

eval { require Auth::ActiveDirectory };
if ($@) {
    plan skip_all => 'Auth::ActiveDirectory required to run these tests';
}

use t::lib::TestApp;
my $app = t::lib::TestApp->to_app;
is( ref $app, "CODE", "Got a code ref" );
test_psgi $app, sub {
    my $cb = shift;

    {
        my $res = $cb->( POST '/login/mziescha/test_pass' );
        is $res->content, 1, 'login fires';
    }

    {
        my $res = $cb->( POST '/list_user/dsonnta/test_pass/test' );
        is $res->content, 1, 'list_user fires';
    }

};

done_testing();

__END__




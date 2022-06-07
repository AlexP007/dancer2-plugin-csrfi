use strict;
use warnings;

use Test::More tests => 1;

package App {
    use Dancer2;
    use Dancer2::Plugin::CSRFI;

    get '/token' => sub {
        return csrf_token;
    };

    post '/validate' => sub {
        return validate_csrf(body_parameters->{csrf_token}) ? 'valid' : 'invalid';
    };
}

use Plack::Test;
use HTTP::Request::Common;
use Data::Dumper;

my $app = Plack::Test->create(App->to_app);
my $result;
my $token;
my $cookie;

# TEST 1 with cookie - should be valid.
$result = $app->request(GET '/token');
$token  = $result->content;

($cookie) =  $result->header('set-cookie') =~ /(dancer\.session=[^;]*)/;

$result = $app->request(
    POST '/validate',
    [csrf_token => $token],
    Cookie => $cookie,
    Referer => 'http://localhost/token'
);

is($result->content, 'valid', 'Test1: valid token with valid session and referer');

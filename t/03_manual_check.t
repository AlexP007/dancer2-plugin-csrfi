use strict;
use warnings;

use Test::More tests => 5;

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

# TEST 2 with cookie but issue two tokens and use first.
$result = $app->request(GET '/token');
$token  = $result->content;

# One more token issue.
$app->request(GET '/token');

($cookie) =  $result->header('set-cookie') =~ /(dancer\.session=[^;]*)/;

$result = $app->request(
    POST '/validate',
    [csrf_token => $token],
    Cookie => $cookie,
    Referer => 'http://localhost/token'
);

is($result->content, 'valid', 'Test2: valid token with valid session and referer after second issue');

# TEST 3 without cookie and referer - should be invalid.
$result = $app->request(GET '/token');
$token  = $result->content;

$result = $app->request(
    POST '/validate',
    [csrf_token => $token]
);

isnt($result->content, 'valid', 'Test3: valid token without session and referer');

# TEST 4 without cookie but with referer - should be invalid.
$result = $app->request(GET '/token');
$token  = $result->content;

$result = $app->request(
    POST '/validate',
    [csrf_token => $token],
    Referer => 'http://localhost/token'
);

isnt($result->content, 'valid', 'Test4: valid token without session but with referer');

# TEST 5 with cookie but without referer - should be invalid.
$result = $app->request(GET '/token');
$token  = $result->content;

($cookie) =  $result->header('set-cookie') =~ /(dancer\.session=[^;]*)/;

$result = $app->request(
    POST '/validate',
    [csrf_token => $token],
    Cookie => $cookie,
);

isnt($result->content, 'valid', 'Test5: valid token with session but without referer');
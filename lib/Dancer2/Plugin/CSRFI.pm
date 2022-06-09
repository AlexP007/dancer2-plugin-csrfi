package Dancer2::Plugin::CSRFI;

use v5.24;
use strict;
use warnings;

use Dancer2::Plugin;
use Dancer2::Core::Hook;
use List::Util qw(any);
use Crypt::SaltedHash;
use Data::UUID;
use Log::Basic;

our $VERSION = '1.00';

plugin_keywords qw(csrf_token validate_csrf);

plugin_hooks qw(after_validate_csrf);

has session_key => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{session_key} || '_csrf' }
);

has refresh => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{refresh} || 0 }
);

has template_token => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{template_token} }
);

has validate_post => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{validate_post} || 0 }
);

has field_name => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{field_name} || 'csrf_token' }
);

has error_status => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{error_status} || 403 }
);

has error_message => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{error_message} || 'Forbidden' }
);

sub BUILD {
    my ($self) = @_;

    if ($self->validate_post) {
        $self->app->add_hook(
            Dancer2::Core::Hook->new(
                name => 'before',
                code => sub { $self->hook_before_request_validate_csrf(@_) },
            )
        );
    }

    if (my $token = $self->template_token) {
        $self->app->add_hook(
            Dancer2::Core::Hook->new(
                name => 'before_template_render',
                code => sub { $_[0]->{$token} = $self->csrf_token }
            )
        );
    }

    return;
}

sub csrf_token {
    my ($self) = @_;

    my $unique;
    my $salt;
    my $hasher;
    my $entropy = $self->page_entropy;
    my $session = $self->app->session->read($self->session_key);

    if (defined $session and not $self->refresh) {
        $unique = $session->{unique};
        $salt   = $session->{salt};
        $hasher = Crypt::SaltedHash->new(salt => $salt);
    }
    else {
        $unique = $self->unique;
        $hasher = Crypt::SaltedHash->new;
        $salt   = $hasher->salt_hex;
    }

    $self->app->session->write(
        $self->session_key => { unique => $unique, salt => $salt }
    );

    return $hasher->add($unique, $entropy)->generate;
}

sub validate_csrf {
    my ($self, $token) = @_;

    if (not defined $token) {
        return;
    }

    my $session = $self->app->session->read($self->session_key);

    if (not defined $session) {
        return;
    }

    my $salt     = $session->{salt};
    my $unique   = $session->{unique};
    my $hasher   = Crypt::SaltedHash->new(salt => $salt);
    my $entropy  = $self->referer_entropy;

    my $expected = $hasher->add($unique, $entropy)->generate;

    return $token eq $expected;
}

sub page_entropy {
    my ($self) = @_;

    my $uri_base = $self->app->request->base;
    $uri_base->path($self->app->request->path);

    return $self->entropy($uri_base);
}

sub referer_entropy {
    my ($self) = @_;
    return $self->entropy($self->app->request->referer || '');
}

sub entropy {
    my ($self, $path) = @_;
    return sprintf(
        '%s:%s',
        $path,
        $self->app->request->address
    );
}

sub unique {
    return Data::UUID->new->create_str;
}

sub hook_before_request_validate_csrf {
    my ($self, $app) = @_;

    if (not $app->request->is_post) {
        return;
    }

    my $content_type      = $app->request->content_type;
    my @html_form_enctype = qw(application/x-www-form-urlencoded multipart/form-data);

    if (not any { $_ eq $content_type } @html_form_enctype) {
        return;
    }

    my $token   = $app->request->body_parameters->{$self->field_name};
    my $success = $self->validate_csrf($token);
    my $referer = $app->request->referer;

    if (not $success) {
        $self->app->log(
            info => {
                message => __PACKAGE__ . ': Token is not valid',
                referer => $referer,
            }
        );
    }
    else {
        $self->app->log(
            debug => {
                message => __PACKAGE__ . ': Token is valid',
                referer => $referer,
            }
        );
    }

    my %after_validate_bag = (
        success       => $success,
        referer       => $referer,
        error_status  => $self->error_status,
        error_message => $self->error_message,
    );

    $self->app->log(
        debug => {
            message => __PACKAGE__ . ': Entering after_validate_csrf hook',
            referer => $referer,
        }
    );

    $self->execute_plugin_hook(
        'after_validate_csrf',
        $app,
        \%after_validate_bag,
    );

    if ($success) {
        return;
    }

    $self->app->log(
        info => {
            message       => __PACKAGE__ . ': Sending error',
            referer       => $referer,
            error_status  => $after_validate_bag{error_status},
            error_message => $after_validate_bag{error_message},
        }
    );

    $app->send_error(
        $after_validate_bag{error_message},
        $after_validate_bag{error_status},
    );
}

1;

__END__
# ABSTRACT: Dancer2 CSRF protection plugin.

=pod

=encoding UTF-8

=head1 NAME

Dancer2::Plugin::CSRFI - Improved CSRF token generation and validation.

=head1 VERSION

version 1.00

=head1 SYNOPSIS

    use Dancer2;
    use use Dancer2::Plugin::CSRFI;

    set plugins => {
        CSRFI => {
            validate_post  => 1,             # this will automate token validation.
            template_token => 'csrf_token',  # token named 'csrf_token' will be available in templates.
        }
    }

    get '/form' => sub {
        template 'form';
    };

    # This route (and other post) is protected with csrf token.
    post '/form' => sub {
        save_data(body_parameters);
    };

=head1 DESCRIPTION

This module is inspired by L<Dancer2::Plugin::CSRF|https://metacpan.org/pod/Dancer2::Plugin::CSRF>
and L<Plack::Middleware::CSRFBlock|https://metacpan.org/pod/Plack::Middleware::CSRFBlock>.

But it's fresh (2022 year release) and will be supported.

=head2 Capabilities

=over 4

=item *
Сan be used in multi-application mode.

=item *
Сan issue and verify CSRF token.

=item *
Can automatically check the token for post requests.

=item*
Has useful hooks (so far one).

=back

=head2 WHY USE CSRF TOKEN

If you are unfamiliar with this topic or want to learn more, read this
L<Cross-Site Request Forgery Prevention Cheat Sheet|https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>.

=head1 AUTHOR

Alexander Panteleev <alexpan at cpan dot org>.

=head1 LICENSE AND COPYRIGHT

This software is copyright (c) 2022 by Alexander Panteleev.
This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
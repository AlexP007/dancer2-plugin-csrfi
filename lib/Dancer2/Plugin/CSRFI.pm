package Dancer2::Plugin::CSRFI;

use v5.24;
use strict;
use warnings;

use Dancer2::Plugin;
use Dancer2::Core::Hook;
use List::Util qw(any);
use Crypt::SaltedHash;
use Data::UUID;

our $VERSION = '0.01';

plugin_keywords qw(csrf_token validate_csrf);

plugin_hooks qw(after_validate_csrf);

has session_key => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{session_key} || '_csrf' }
);

has once_per_session => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{once_per_session} || 1 }
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

has send_error => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{show_error} || 0 }
);

has error_status => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{response_status} || 403 }
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

    return;
}

sub csrf_token {
    my ($self) = @_;

    my $unique;
    my $entropy = $self->page_entropy;
    my $session = $self->app->session->read($self->session_key);

    if (defined $session and $self->once_per_session) {
        $unique = $session->{unique};
    }
    else {
        $unique = $self->unique;
    }

    $self->app->session->write($self->session_key => { unique => $unique });

    return $self->generate($unique, $entropy);

}

sub validate_csrf {
    my ($self, $token) = @_;

    my $session = $self->app->session->read($self->session_key);

    if (not defined $session) {
        return;
    }

    my $unique   = $session->{unique};
    my $entropy  = $self->referer_entropy;
    my $expected = $self->generate($unique, $entropy);

    return $token eq $expected;

}

sub page_entropy {
    my ($self) = @_;
    return $self->entropy($self->app->request->base . $self->app->request->path);
}

sub referer_entropy {
    my ($self) = @_;
    return $self->entropy($self->app->request->referer);
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

sub generate {
    my ($self, $unique, $path) = @_;
    return $self->hash->add($unique, $path)->generate;
}

sub hash {
    return Crypt::SaltedHash->new;
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
        send_error    => $self->send_error,
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

    if (not $after_validate_bag{show_error}) {
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
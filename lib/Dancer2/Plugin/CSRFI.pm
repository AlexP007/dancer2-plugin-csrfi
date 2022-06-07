package Dancer2::Plugin::CSRFI;

use v5.24;
use strict;
use warnings;

use Dancer2::Plugin;
use Dancer2::Core::Hook;
use Crypt::SaltedHash;
use Data::UUID;
use namespace::clean;

our $VERSION = '0.01';

plugin_keywords qw(csrf_token validate_csrf);

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

has response_status => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{response_status} || 403 }
);

sub BUILD {
    my ($self) = @_;

    $self->app->add_hook(
        Dancer2::Core::Hook->new(
            name => 'before',
            code => sub { $self->hook_before_request_validate_csrf(@_) }
        )
    );
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
    my $entropy  = $self->page_entropy;
    my $expected = $self->generate($unique, $entropy);

    return $token eq $expected;

}

sub page_entropy {
    my ($self) = @_;
    return $self->entropy($self->request->base . $self->request->path);
}

sub referer_entropy {
    my ($self) = @_;
    return $self->entropy($self->request->referer);
}

sub entropy {
    my ($self, $path) = @_;
    return sprintf(
        '%s:%s',
        $path,
        $self->request->address
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

    my $success = 0;

    if (not $success) {
        $self->app->log(
            warning => __PACKAGE__ . ': Token is not valid'
        );
    }
    else {
        $self->app->log(
            info => __PACKAGE__ . ': Token is valid'
        );
    }

    my %after_validate_bag = (
        success => $success,
    );

    $self->app->log(
        debug => __PACKAGE__ . ': Entering after_validate_csrf hook'
    );

    $self->execute_plugin_hook(
        'after_validate_csrf',
        $app,
        \%after_validate_bag,
    );
}

1;

__END__
# ABSTRACT: Dancer2 CSRF protection plugin.
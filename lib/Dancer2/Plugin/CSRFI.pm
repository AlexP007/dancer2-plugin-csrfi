package Dancer2::Plugin::CSRFI;

use v5.24;
use strict;
use warnings;

use Dancer2::Plugin;
use Dancer2::Core::Hook;

our $VERSION = '0.01';

plugin_keywords qw(csrf_token validate_csrf);

has session_key => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{session_key} || '_csrf' }
);

has validate_post => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->config->{validate_post} || 0 }
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

}

sub validate_csrf {

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
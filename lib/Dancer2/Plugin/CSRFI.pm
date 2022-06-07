package Dancer2::Plugin::CSRFI;

use v5.24;
use strict;
use warnings;

use Dancer2::Plugin;
use Dancer2::Core::Hook;

our $VERSION = '0.01';

plugin_keywords qw(csrf_token validate_csrf);

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

    my %after_validate_bag = (
        success => $success,
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
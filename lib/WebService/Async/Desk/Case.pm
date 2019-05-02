package WebService::Async::Desk::Case;

use strict;
use warnings;

use parent qw(WebService::Async::Desk::Base::Case);

use Future::AsyncAwait;

sub new { my $class = shift; bless { @_[0..$#_] }, $class }

sub desk { shift->{desk} }

async sub close {
    my ($self) = @_;
    await $self->desk->case_update(
        id     => $self->id,
        status => 'closed',
    );
}

1;

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

sub link_list {
    my ($self, %args) = @_;
    return $self->desk->link_list(
        case => $self,
        %args
    );
}

sub reply_list {
    my ($self, %args) = @_;
    return $self->desk->reply_list(
        case => $self,
        %args
    );
}

sub note_list {
    my ($self, %args) = @_;
    return $self->desk->note_list(
        case => $self,
        %args
    );
}

sub attachment_list {
    my ($self, %args) = @_;
    return $self->desk->attachment_list(
        case => $self,
        %args
    );
}
1;

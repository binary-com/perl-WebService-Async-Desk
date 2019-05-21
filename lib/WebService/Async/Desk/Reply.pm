package WebService::Async::Desk::Reply;

use strict;
use warnings;

use parent qw(WebService::Async::Desk::Base::Reply);

use Future::AsyncAwait;

sub new {
    my ($class, %args) = @_;
    Scalar::Util::weaken($args{$_}) for grep exists $args{$_}, qw(case desk);
    bless \%args, $class
}

sub desk { shift->{desk} }
sub case { shift->{case} }

sub id { (shift->{_links}{self}{href} =~ /([0-9]+)$/)[0] }

1;

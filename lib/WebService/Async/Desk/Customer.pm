package WebService::Async::Desk::Customer;

use strict;
use warnings;

use parent qw(WebService::Async::Desk::Base::Customer);

sub new { my $class = shift; bless { @_[0..$#_] }, $class }

1;

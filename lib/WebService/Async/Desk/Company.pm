package WebService::Async::Desk::Company;

use strict;
use warnings;

sub new { bless { @_[1..$#_] }, $_[0] }

sub id { shift->{id} }
sub custom_fields { shift->{custom_fields} }
sub labels { shift->{labels} }
sub created_at { shift->{created_at} }
sub domains { shift->{domains} }
sub updated_at { shift->{updated_at} }
sub name { shift->{name} }

1;


package WebService::Async::Desk::Base::Group;

use strict;
use warnings;

# VERSION

=head1 NAME

WebService::Async::Desk::Base::Group - support for desk.com entity

=head1 DESCRIPTION

This is autogenerated from the L<https://www.desk.com> API documentation.

=cut

=head1 METHODS - Attributes

=head2 id

id for this resource.

=cut

sub id : method { shift->{id} }

=head2 name

name of group.

=cut

sub name : method { shift->{name} }

1;

__END__

=head1 AUTHOR

binary.com C<< BINARY@cpan.org >>

=head1 LICENSE

Copyright binary.com 2017-2019. Licensed under the same terms as Perl itself.


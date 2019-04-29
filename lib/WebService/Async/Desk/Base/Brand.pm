package WebService::Async::Desk::Base::Brand;

use strict;
use warnings;

# VERSION

=head1 NAME

WebService::Async::Desk::Base::Brand - support for desk.com entity

=head1 DESCRIPTION

This is autogenerated from the L<https://www.desk.com> API documentation.

=cut

=head1 METHODS - Attributes

=head2 name

name of the brand.

=cut

sub name : method { shift->{name} }

=head2 created_at

when the brand was created.

=cut

sub created_at : method { shift->{created_at} }

=head2 updated_at

when the brand was last updated.

=cut

sub updated_at : method { shift->{updated_at} }

1;

__END__

=head1 AUTHOR

binary.com C<< BINARY@cpan.org >>

=head1 LICENSE

Copyright binary.com 2017-2019. Licensed under the same terms as Perl itself.


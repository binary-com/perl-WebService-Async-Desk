package WebService::Async::Desk::Base::Macro;

use strict;
use warnings;

# VERSION

=head1 NAME

WebService::Async::Desk::Base::Macro - support for desk.com entity

=head1 DESCRIPTION

This is autogenerated from the L<https://www.desk.com> API documentation.

=cut

=head1 METHODS - Attributes

=head2 name

name of the macro.

=cut

sub name : method { shift->{name} }

=head2 description

an optional description.

=cut

sub description : method { shift->{description} }

=head2 enabled

whether or not the macro is enabled for use.

=cut

sub enabled : method { shift->{enabled} }

=head2 position

placement in the UI.

=cut

sub position : method { shift->{position} }

=head2 folders

array of folders associated with this macro.

=cut

sub folders : method { shift->{folders} }

1;

__END__

=head1 AUTHOR

binary.com C<< BINARY@cpan.org >>

=head1 LICENSE

Copyright binary.com 2017-2019. Licensed under the same terms as Perl itself.


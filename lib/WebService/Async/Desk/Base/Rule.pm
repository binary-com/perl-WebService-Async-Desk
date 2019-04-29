package WebService::Async::Desk::Base::Rule;

use strict;
use warnings;

# VERSION

=head1 NAME

WebService::Async::Desk::Base::Rule - support for desk.com entity

=head1 DESCRIPTION

This is autogenerated from the L<https://www.desk.com> API documentation.

=cut

=head1 METHODS - Attributes

=head2 name

the rule's name.

=cut

sub name : method { shift->{name} }

=head2 description

an optional description.

=cut

sub description : method { shift->{description} }

=head2 enabled

whether or not this rule will run.

=cut

sub enabled : method { shift->{enabled} }

=head2 created_at

when this rule was created.

=cut

sub created_at : method { shift->{created_at} }

=head2 updated_at

when this rule was last updated.

=cut

sub updated_at : method { shift->{updated_at} }

1;

__END__

=head1 AUTHOR

binary.com C<< BINARY@cpan.org >>

=head1 LICENSE

Copyright binary.com 2017-2019. Licensed under the same terms as Perl itself.

package WebService::Async::Desk::Base::Topic;

use strict;
use warnings;

# VERSION

=head1 NAME

WebService::Async::Desk::Base::Topic - support for desk.com entity

=head1 DESCRIPTION

This is autogenerated from the L<https://www.desk.com> API documentation.

=cut

=head1 METHODS - Attributes

=head2 name

subject of the topic translated to the default locale.

=cut

sub name : method { shift->{name} }

=head2 description

an optional description of the topic.

=cut

sub description : method { shift->{description} }

=head2 position

topic's position in the Admin UI.

=cut

sub position : method { shift->{position} }

=head2 allow_questions

If true, allow customers to post questions about this topic in your Support Center.

=cut

sub allow_questions : method { shift->{allow_questions} }

=head2 in_support_center

If true, show this topic in your Support Center.

=cut

sub in_support_center : method { shift->{in_support_center} }

=head2 created_at

time when the topic was created.

=cut

sub created_at : method { shift->{created_at} }

=head2 updated_at

time when the topic was last updated at.

=cut

sub updated_at : method { shift->{updated_at} }

1;

__END__

=head1 AUTHOR

binary.com C<< BINARY@cpan.org >>

=head1 LICENSE

Copyright binary.com 2017-2019. Licensed under the same terms as Perl itself.


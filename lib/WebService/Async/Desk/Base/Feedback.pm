package WebService::Async::Desk::Base::Feedback;

use strict;
use warnings;

# VERSION

=head1 NAME

WebService::Async::Desk::Base::Feedback - support for desk.com entity

=head1 DESCRIPTION

This is autogenerated from the L<https://www.desk.com> API documentation.

=cut

=head1 METHODS - Attributes

=head2 id

string identifier for this object.

=cut

sub id : method { shift->{id} }

=head2 rating

Numeric rating left by customer.

=cut

sub rating : method { shift->{rating} }

=head2 rating_type

Rating type used to generate this feedback, either yes_no or four_star.

=cut

sub rating_type : method { shift->{rating_type} }

=head2 additonal_feedback

An optional additional feedback text field.

=cut

sub additonal_feedback : method { shift->{additonal_feedback} }

=head2 created_at

Date the feedback was created.

=cut

sub created_at : method { shift->{created_at} }

=head2 updated_at

Date the feedback was updated.

=cut

sub updated_at : method { shift->{updated_at} }

1;

__END__

=head1 AUTHOR

binary.com C<< BINARY@cpan.org >>

=head1 LICENSE

Copyright binary.com 2017-2019. Licensed under the same terms as Perl itself.

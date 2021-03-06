package WebService::Async::Desk::Base::User;

use strict;
use warnings;

# VERSION

=head1 NAME

WebService::Async::Desk::Base::User - support for desk.com entity

=head1 DESCRIPTION

This is autogenerated from the L<https://www.desk.com> API documentation.

=cut

=head1 METHODS - Attributes

=head2 id

id for this resource.

=cut

sub id : method { shift->{id} }

=head2 name

name of the user.

=cut

sub name : method { shift->{name} }

=head2 public_name

public facing name of the user.

=cut

sub public_name : method { shift->{public_name} }

=head2 email

user's email.

=cut

sub email : method { shift->{email} }

=head2 email_verified

indicates if an email address has been verified.

=cut

sub email_verified : method { shift->{email_verified} }

=head2 avatar

user's avatar URL - image sourced from Gravatar..

=cut

sub avatar : method { shift->{avatar} }

=head2 level

user's permission level.

=cut

sub level : method { shift->{level} }

=head2 created_at

when this record was created.

=cut

sub created_at : method { shift->{created_at} }

=head2 updated_at

when this record was last updated.

=cut

sub updated_at : method { shift->{updated_at} }

=head2 current_login_at

when this user most recently logged in.

=cut

sub current_login_at : method { shift->{current_login_at} }

=head2 last_login_at

when this user last logged in.

=cut

sub last_login_at : method { shift->{last_login_at} }

=head2 available

true when user is online with routing enabeld, false otherwise.

=cut

sub available : method { shift->{available} }

1;

__END__

=head1 AUTHOR

binary.com C<< BINARY@cpan.org >>

=head1 LICENSE

Copyright binary.com 2017-2019. Licensed under the same terms as Perl itself.


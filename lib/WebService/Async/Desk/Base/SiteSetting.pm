package WebService::Async::Desk::Base::SiteSetting;

use strict;
use warnings;

# VERSION

=head1 NAME

WebService::Async::Desk::Base::SiteSetting - support for desk.com entity

=head1 DESCRIPTION

This is autogenerated from the L<https://www.desk.com> API documentation.

=cut

=head1 METHODS - Attributes

=head2 agent_inactivity_timeout_full

Amount of inactivity for flex agents, before the agent session is suspended..

=cut

sub agent_inactivity_timeout_full : method { shift->{agent_inactivity_timeout_full} }

=head2 agent_inactivity_timeout_flex

Amount of inactivity for full time agents, before the agent session is suspended..

=cut

sub agent_inactivity_timeout_flex : method { shift->{agent_inactivity_timeout_flex} }

=head2 agent_name_descriptor

Agent Descriptor; returns a string..

=cut

sub agent_name_descriptor : method { shift->{agent_name_descriptor} }

=head2 allow_screenpop_ignore_enabled

Whether to allow agents to continue working while the screenpop is displayed..

=cut

sub allow_screenpop_ignore_enabled : method { shift->{allow_screenpop_ignore_enabled} }

=head2 auto_assign_case_on_open_enabled

Whether to automatically assign the case to the Agent who opened it..

=cut

sub auto_assign_case_on_open_enabled : method { shift->{auto_assign_case_on_open_enabled} }

=head2 case_routing_method

Provides status of case routing, returns one of the following: enabled, disabled or by_case_filter..

=cut

sub case_routing_method : method { shift->{case_routing_method} }

=head2 company_name

Company name specified in site settings..

=cut

sub company_name : method { shift->{company_name} }

=head2 email_address_books_agent_enabled

Allow autocomplete for agent email addresses in the TO, CC, BCC fields of a case reply.  Returns true or false..

=cut

sub email_address_books_agent_enabled : method { shift->{email_address_books_agent_enabled} }

=head2 email_address_books_customer_enabled

Allow autocomplete for customer email addresses in the TO, CC, BCC fields of a case reply.  Returns true or false..

=cut

sub email_address_books_customer_enabled : method { shift->{email_address_books_customer_enabled} }

=head2 email_address_books_user_input_enabled

Allow autocomplete for added email addresses in the TO, CC, BCC fields of a case reply. Returns true or false..

=cut

sub email_address_books_user_input_enabled : method { shift->{email_address_books_user_input_enabled} }

=head2 enable_feedback

Customer feedback; can be true or false..

=cut

sub enable_feedback : method { shift->{enable_feedback} }

=head2 multi_lang_enabled

Whether Multilingual Support is enabled; can be true or false..

=cut

sub multi_lang_enabled : method { shift->{multi_lang_enabled} }

=head2 multi_brand_enabled

Allows you to use multiple Support Centers on a single Desk.com account..

=cut

sub multi_brand_enabled : method { shift->{multi_brand_enabled} }

=head2 open_cti_enabled

Phone Integrations status; can be true or false..

=cut

sub open_cti_enabled : method { shift->{open_cti_enabled} }

=head2 portal_authentication_type

The method of authentication customers use to access your portal.  Returns "1" for No Authentication, "2" for Desk.com or "3" for Multipass..

=cut

sub portal_authentication_type : method { shift->{portal_authentication_type} }

=head2 portal_require_authentication_type

Require authentication for a particular interaction: returns "1" for No authentication for anything, "2" for Interactions, or "3" for everything..

=cut

sub portal_require_authentication_type : method { shift->{portal_require_authentication_type} }

=head2 queue_screenpop_timeout

The amount of time, in seconds, the case routing screen popup appears for the Agent..

=cut

sub queue_screenpop_timeout : method { shift->{queue_screenpop_timeout} }

=head2 queue_service_level_warn

Service level warning threshold percentage..

=cut

sub queue_service_level_warn : method { shift->{queue_service_level_warn} }

=head2 route_one_case_enabled

Route one case at a time; can be true or false..

=cut

sub route_one_case_enabled : method { shift->{route_one_case_enabled} }

=head2 set_status_pending_on_open_enabled

Automatically change the case status to Pending, after the specified action. Return values can be: save_to_pending_on_reply_save, change_to_pending_on_case_open or no_status_changes..

=cut

sub set_status_pending_on_open_enabled : method { shift->{set_status_pending_on_open_enabled} }

=head2 timezone

Timezone setting for the site. Returns string, e.g., "Eastern Time (US & Canada)"..

=cut

sub timezone : method { shift->{timezone} }

=head2 undo_send_enabled

Whether to allow agents to recall a sent Email, Twitter, or Facebook interaction within 10 seconds..

=cut

sub undo_send_enabled : method { shift->{undo_send_enabled} }

1;

__END__

=head1 AUTHOR

binary.com C<< BINARY@cpan.org >>

=head1 LICENSE

Copyright binary.com 2017-2019. Licensed under the same terms as Perl itself.

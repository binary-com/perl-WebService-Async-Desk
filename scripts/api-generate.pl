#!/usr/bin/env perl 
use strict;
use warnings;

# Simple helper script to generate the API classes

use Syntax::Keyword::Try;
use IO::Async::Loop;
use Net::Async::HTTP;
use Path::Tiny;
use HTML::TreeBuilder;
use Template;
use List::UtilsBy qw(extract_by);

use Log::Any qw($log);
use Log::Any::Adapter qw(Stderr), log_level => 'trace';

my $loop = IO::Async::Loop->new;
$loop->add(
    my $ua = Net::Async::HTTP->new
);

my $tt = Template->new(
    ENCODING => 'UTF-8',
);
my %map_types = (
    replies => 'cases',
    links => 'cases',
    attachments => 'cases',
    notes => 'cases',
);
for my $type (qw(
    cases articles customers brands custom-fields groups feedbacks insights jobs
    labels macros permissions rules site-settings snippets system-message topics users
    replies links attachments notes
)) {
    my $data = do {
        my $local_type = $map_types{$type} // $type;
        my $path = path($local_type . '.html');
        $path->exists ? $path->slurp_utf8 : do {
            my $resp = $ua->GET('http://dev.desk.com/API/' . $local_type)->get;
            $path->spew_utf8(my $txt = $resp->decoded_content);
            $txt
        }
    };
    try {
        my $html = HTML::TreeBuilder->new(no_space_compacting => 1);
        $html->parse($data);
        $html->eof;
        # Depluralised version of the type - nasty custom logic in here, but given that this isn't
        # ever likely to change we can get away with it for now.
        my $entity_name = ucfirst $type;
        $entity_name = 'Company' if $type eq 'companies';
        $entity_name = 'Reply' if $type eq 'replies';
        $entity_name =~ s{s$}{};
        $entity_name =~ s{-(.)}{\U$1}g;

        my $section_id = $map_types{$type} ? $type . '-fields' : 'fields';
        warn $html->look_down(
            id => $section_id
        ) . ' for ' . $section_id;
        my ($section) = map {
            $_->look_down(_tag => 'table')
        } $html->look_down(
            id => $section_id
        );

        my @fields;
        for my $row ($section->look_down(_tag => 'tr')) {
            my ($k, $description) = map $_->as_text, $row->look_down(_tag => 'td');
            next unless defined $k;
            # $log->infof('Have %s => %s', $k, $description);
            push @fields, {
                name        => $k,
                description => $description
            };
            $log->infof('%s', $k);
        }
        $tt->process(\q{[% -%]
package WebService::Async::Desk::Base::[% entity_name %];

use strict;
use warnings;

# VERSION

=head1 NAME

WebService::Async::Desk::Base::[% entity_name %] - support for desk.com entity

=head1 DESCRIPTION

This is autogenerated from the L<https://www.desk.com> API documentation.

=cut

=head1 METHODS - Attributes

[%  FOR field IN field_list -%]
=head2 [% field.name %]

[% field.description %].

=cut

sub [% field.name %] : method { shift->{[% field.name %]} }

[% END -%]
1;

__END__

=head1 AUTHOR

binary.com C<< BINARY@cpan.org >>

=head1 LICENSE

Copyright binary.com 2017-2019. Licensed under the same terms as Perl itself.

}, { entity_name => $entity_name, field_list => \@fields }, 'lib/WebService/Async/Desk/Base/' . $entity_name . '.pm') or die $tt->error;
    } catch {
        $log->errorf('Failed to process %s - %s', $type, $@);
    }
}

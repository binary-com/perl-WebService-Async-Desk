package WebService::Async::Desk;
# ABSTRACT: Support for the desk.com customer service ERM

use strict;
use warnings;

our $VERSION = '1.000';

use parent qw(IO::Async::Notifier);

no indirect;
use mro;
use Syntax::Keyword::Try;
use Log::Any qw($log);
use URI;
use URI::QueryParam;
use Net::Async::OAuth::Client;
use Net::Async::HTTP;
use JSON::MaybeUTF8 qw(:v1);
use Future::AsyncAwait;
use Ryu::Async;
use Future::Utils qw(repeat);

use WebService::Async::Desk::Customer;
use WebService::Async::Desk::Case;
use WebService::Async::Desk::Reply;
use WebService::Async::Desk::Note;
use WebService::Async::Desk::Attachment;

sub configure {
    my ($self, %args) = @_;
    for(qw(key secret token token_secret ua)) {
        $self->{$_} = delete $args{$_} if exists $args{$_};
    }
    for(qw(base_uri)) {
        $self->{$_} = URI->new('' . delete($args{$_})) if exists $args{$_};
    }
    return $self->next::method(%args);
}

sub key { shift->{key} }

sub secret { shift->{secret} }

sub token { shift->{token} }

sub token_secret { shift->{token_secret} }

sub base_uri { shift->{base_uri} //= URI->new('https://desk.com') }

sub oauth {
    my ($self) = @_;
    $self->{oauth} //= Net::Async::OAuth::Client->new(
        realm           => 'desk.com',
        consumer_key    => $self->key,
        consumer_secret => $self->secret,
        token           => $self->token,
        token_secret    => $self->token_secret,
    )
}

sub ua {
    my ($self) = @_;
    $self->{ua} //= do {
        $self->add_child(
            my $ua = Net::Async::HTTP->new(
                fail_on_error            => 1,
                decode_content           => 1,
                pipeline                 => 1,
                stall_timeout            => 60,
                max_connections_per_host => 4,
                user_agent               => 'Mozilla/4.0 (WebService::Async::Desk; BINARY@cpan.org; https://metacpan.org/pod/WebService::Async::Desk)',
            )
        );
        $ua
    }
}

sub http_get {
    my ($self, %args) = @_;

    $args{headers}{Authorization} = $self->oauth->authorization_header(
        method => 'GET',
        uri => $args{uri}
    );

    $log->tracef("GET %s { %s }", ''. $args{uri}, \%args);
    $self->ua->GET(
        (delete $args{uri}),
        %args
    )->then(sub {
        my ($resp) = @_;
        $log->tracef("%s => %s", $args{uri}, $resp->decoded_content);
        return { } if $resp->code == 204;
        return { } if 3 == ($resp->code / 100);
        try {
            return Future->done(decode_json_utf8($resp->content))
        } catch {
            $log->errorf("JSON decoding error %s from HTTP response %s", $@, $resp->as_string("\n"));
            return Future->fail($@ => json => $resp);
        }
    })->else(sub {
        my ($err, $src, $resp, $req) = @_;
        $src //= '';
        if($src eq 'http') {
            $log->errorf("HTTP error %s, request was %s with response %s", $err, $req->as_string("\n"), $resp->as_string("\n"));
        } else {
            $log->errorf("Other failure (%s): %s", $src // 'unknown', $err);
        }
        Future->fail(@_);
    })
}

sub http_patch {
    my ($self, %args) = @_;

    $args{headers}{Authorization} = $self->oauth->authorization_header(
        method => 'PATCH',
        uri    => $args{uri}
    );

    $log->tracef("PATCH %s { %s }", ''. $args{uri}, \%args);
    my $req = HTTP::Request->new(
        PATCH => delete $args{uri},
        [
            (delete $args{headers})->%*,
            'Content-Type' => 'application/json',
        ],
        encode_json_utf8($args{content})
    );
    $log->tracef('Request is %s', $req->as_string("\n"));
    $self->ua->do_request(
        request => $req,
    )->then(sub {
        my ($resp) = @_;
        $log->tracef("%s => %s", $args{uri}, $resp->decoded_content);
        return { } if $resp->code == 204;
        return { } if 3 == ($resp->code / 100);
        try {
            return Future->done(decode_json_utf8($resp->content))
        } catch {
            $log->errorf("JSON decoding error %s from HTTP response %s", $@, $resp->as_string("\n"));
            return Future->fail($@ => json => $resp);
        }
    })->else(sub {
        my ($err, $src, $resp, $req) = @_;
        $src //= '';
        if($src eq 'http') {
            $log->errorf("HTTP error %s, request was %s with response %s", $err, $req->as_string("\n"), $resp->as_string("\n"));
        } else {
            $log->errorf("Other failure (%s): %s", $src // 'unknown', $err);
        }
        Future->fail(@_);
    })
}

=head2 oauth

Given a coderef, will go through the OAuth process and
call the code if necessary to get the verification token.

Resolves to the access token details that should be passed
to the API if required.

=cut

async sub oauth_login {
    my ($self, $code) = @_;
    $self->oauth->configure(
        token        => '',
        token_secret => '',
    );
    my $uri = URI->new('https://binary.desk.com/oauth/authorize');
    my $req = HTTP::Request->new(POST => "$uri");
    $req->protocol('HTTP/1.1');
    my $hdr = $self->oauth->authorization_header(
        method => 'POST',
        uri    => $uri,
    );
    $req->header('Authorization' => $hdr);
    $req->header('Host' => $uri->host);
    $log->tracef("Resulting auth header was %s", $hdr);
    $req->header('Connection' => 'close');
    $req->header('Accept' => '*/*');
    try {
        my ($resp) = await $self->ua->do_request(
            request => $req,
        );
        $log->debugf("RequestToken response was %s", $resp->as_string("\n"));
        my $rslt = URI->new('http://localhost?' . $resp->decoded_content)->query_form_hash;
        $log->debugf("Extracted token [%s]", $rslt->{oauth_token});
        $self->oauth->configure(token => $rslt->{oauth_token});
        $log->debugf("Extracted secret [%s]", $rslt->{oauth_token_secret});
        $self->oauth->configure(token_secret => $rslt->{oauth_token_secret});

        my $auth_uri = $self->base_uri->clone;
        $auth_uri->path(
            '/oauth/request_token'
        );
        $auth_uri->query_param(oauth_token => $rslt->{oauth_token});
        $auth_uri->query_param(scope       => 'read,write');
        $auth_uri->query_param(name        => 'desk');
        $auth_uri->query_param(expiration  => 'never');
        
        my ($verify) = await $code->($auth_uri);

        my $uri = $self->base_uri->clone;
        $uri->path('/oauth/access_token');
        my $req = HTTP::Request->new(POST => "$uri");
        $req->protocol('HTTP/1.1');

        my $hdr = $self->oauth->authorization_header(
            method => 'POST',
            uri    => $uri,
            parameters => {
                oauth_verifier => $verify
            }
        );
        $req->header('Authorization' => $hdr);
        $log->tracef("Resulting auth header was %s", $hdr);

        $req->header('Host' => $uri->host);
        $req->header('Connection' => 'close');
        $req->header('Accept' => '*/*');
        ($resp) = await $self->ua->do_request(
            request => $req,
        );
        $log->tracef("GetAccessToken response was %s", $resp->as_string("\n"));

        $rslt = URI->new('http://localhost?' . $resp->decoded_content)->query_form_hash;
        $log->tracef("Extracted token [%s]", $rslt->{oauth_token});
        $self->configure(token => $rslt->{oauth_token});
        $log->tracef("Extracted secret [%s]", $rslt->{oauth_token_secret});
        $self->configure(token_secret => $rslt->{oauth_token_secret});
        return {
            token        => $rslt->{oauth_token},
            token_secret => $rslt->{oauth_token_secret},
        };
    } catch {
        $log->errorf("Failed to do oauth lookup - %s", join ',', @_);
        die @_;
    }
}

sub ryu {
    my ($self) = @_;
    $self->{ryu} //= do {
        $self->add_child(
            my $ryu = Ryu::Async->new
        );
        $ryu
    }
}

sub source {
    shift->ryu->source
}

=head2 paging

Supports paging through HTTP GET requests.

=over 4

=item * C<$starting_uri> - the initial L<URI> to request

=item * C<$factory> - a C<sub> that we will call with a L<Ryu::Source> and expect to return
a second response-processing C<sub>.

=back

Returns a L<Ryu::Source>.

=cut

sub paging {
    my ($self, $starting_uri, $factory) = @_;
    my $uri = ref($starting_uri)
    ? $starting_uri->clone
    : URI->new($starting_uri);

    my $src = $self->source;
    my $f = $src->completed;
    my $code = $factory->($src);
    (repeat {
        $log->tracef('GET %s', "$uri");
        $self->rate_limiting->then(sub {
            $self->http_get(uri => $uri)
        })->then(sub {
            try {
                my ($data) = @_;
                $log->tracef('Have response %s', $data);
                my ($total) = $data->{total_entries};
                $log->tracef('Expected total count %d', $total);
                $code->($data);
                $log->tracef('Links are %s', $data->{_links});
                if(my $next = $data->{_links}{next}{href}) {
                    $uri->path_query($next);
                } else {
                    $f->done unless $f->is_ready;
                }
                return Future->done;
            } catch {
                my ($err) = $@;
                $log->errorf('Failed - %s', $err);
                return Future->fail($err);
            }
        }, sub {
            my ($err, @details) = @_;
            $log->errorf('Failed to request %s: %s', $uri, $err);
            $src->completed->fail($err, @details) unless $src->completed->is_ready;
            Future->fail($err, @details);
        })
    } until => sub { $f->is_ready })->retain;
    return $src;
}

=head2 rate_limiting

Applies rate limiting check.

Returns a L<Future> which will resolve once it's safe to send further requests.

=cut

sub rate_limiting {
    my ($self) = @_;
    $self->{rate_limit} //= do {
        $self->loop->delay_future(
            after => 60
        )->on_ready(sub {
            $self->{request_count} = 0;
            delete $self->{rate_limit};
        })
    };
    return Future->done unless $self->requests_per_minute and ++$self->{request_count} >= $self->requests_per_minute;
    return $self->{rate_limit};
}

sub requests_per_minute { shift->{requests_per_minute} //= 300 }

my %type_plural = (
    case       => 'cases',
    customer   => 'customers',
    company    => 'companies',
    reply      => 'replies',
    link       => 'links',
    note       => 'notes',
    attachment => 'attachments',
);
my %package_name_map = ();
for (keys %type_plural) {
    my $type = $_;
    my $plural = $type_plural{$type};
    my $pkg = 'WebService::Async::Desk::' . ($package_name_map{$type} // ucfirst($type));
    {
        my $code = sub {
            my ($self, %args) = @_;

            my $uri = $self->base_uri->clone;
            my %extra;
            if(my $case = delete $args{case}) {
                $uri->path('/api/v2/cases/' . $case->id . '/' . $plural);
                $extra{case} = $case;
                $extra{case_id} = $case->id;
            } elsif(my $case_id = delete $args{case_id}) {
                $uri->path('/api/v2/cases/' . $case_id . '/' . $plural);
                $extra{case_id} = $case_id;
            } else {
                $uri->path('/api/v2/' . $plural);
            }
            $uri->query_param(per_page => 200);
            $uri->query_param($_ => $args{$_}) for keys %args;
            return $self->paging($uri => sub {
                my ($src) = @_;
                sub {
                    my ($data) = @_;
                    for my $item ($data->{_embedded}{entries}->@*) {
                        last if $src->completed->is_ready;
                        my $entry = $pkg->new(desk => $self, %extra, %$item);
                        $src->emit($entry);
                    }
                }
            });
        };
        my $method_name = $type . '_list';
        {
            no strict 'refs';
            *$method_name = $code unless __PACKAGE__->can($method_name);
        }
    }
    {
        my $code = async sub {
            my ($self, @args) = @_;

            my %args = @args > 1 ? @args : (id => @args);
            my $uri = $self->base_uri->clone;
            $uri->path('/api/v2/' . $plural . '/' . $args{id});
            my ($res) = await $self->http_get(
                uri => $uri,
            );
            return $pkg->new(desk => $self, $res->%*);
        };
        my $method_name = $type . '_by_id';
        {
            no strict 'refs';
            *$method_name = $code unless __PACKAGE__->can($method_name);
        }
    }
    {
        my $code = async sub {
            my ($self, @args) = @_;

            my %args = (@args > 1)
            ? @args
            : (id => @args);
            my $id = delete $args{id};
            my $uri = $self->base_uri->clone;
            $uri->path('/api/v2/' . $plural . '/' . $id);
            my ($res) = await $self->http_patch(
                uri    => $uri,
                content => \%args
            );
            return $pkg->new(desk => $self, $res->%*);
        };
        my $method_name = $type . '_update';
        {
            no strict 'refs';
            *$method_name = $code unless __PACKAGE__->can($method_name);
        }
    }
}

1;

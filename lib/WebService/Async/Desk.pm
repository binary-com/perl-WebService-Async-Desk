package WebService::Async::Desk;
# ABSTRACT: Support for the desk.com customer service ERM

use strict;
use warnings;

our $VERSION = '1.000';

use parent qw(IO::Async::Notifier);

use mro;
use Syntax::Keyword::Try;
use Log::Any qw($log);
use URI;
use URI::QueryParam;
use Net::Async::OAuth::Client;
use JSON::MaybeUTF8 qw(:v1);
use Future::AsyncAwait;
use Ryu::Async;

use WebService::Async::Desk::Customer;
use WebService::Async::Desk::Case;

sub configure {
    my ($self, %args) = @_;
    for(qw(key secret token token_secret http)) {
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

sub http { shift->{http} }

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

sub http_get {
    my ($self, %args) = @_;

    $args{headers}{Authorization} = $self->oauth->authorization_header(
        method => 'GET',
        uri => $args{uri}
    );

    $log->tracef("GET %s { %s }", ''. $args{uri}, \%args);
    $self->http->GET(
        (delete $args{uri}),
        %args
    )->then(sub {
        my ($resp) = @_;
        $log->tracef("%s => %s", $args{uri}, $resp->decoded_content);
        return { } if $resp->code == 204;
        return { } if 3 == ($resp->code / 100);
        try {
            return Future->done(decode_json_text($resp->decoded_content))
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
        uri => $args{uri}
    );

    $log->tracef("PATCH %s { %s }", ''. $args{uri}, \%args);
    my $req = HTTP::Request->new(
        PATCH => delete $args{uri},
        [
            (delete $args{headers})->%*,
            'Content-Type' => 'application/json',
        ],
        encode_json_utf8(\%args)
    );
    $self->http->do_request(
        request => $req,
    )->then(sub {
        my ($resp) = @_;
        $log->tracef("%s => %s", $args{uri}, $resp->decoded_content);
        return { } if $resp->code == 204;
        return { } if 3 == ($resp->code / 100);
        try {
            return Future->done(decode_json_text($resp->decoded_content))
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
        my ($resp) = await $self->http->do_request(
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
        ($resp) = await $self->http->do_request(
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

sub new_source {
    shift->ryu->source
}

sub company_list {
	my ($self, %args) = @_;

    my $src = $self->new_source;
    my $uri = $self->base_uri->clone;
    $uri->path('/api/v2/companies');
    $self->http_get(
        uri => $uri,
    )->then(sub {
        my ($res) = @_;
        try {
            $src->emit($_) for map { WebService::Async::Desk::Company->new(desk => $self, %$_) } $res->{_embedded}{entries}->@*;
            $src->done;
            Future->done;
        } catch {
            $log->errorf('Failed - %s', $@);
            Future->fail($@);
        }
    })->retain;
    return $src;
}

my %type_plural = (
    case => 'cases',
    customer => 'customers',
    company => 'companies',
);
my %package_name_map = ();
for (qw(case customer company)) {
    my $type = $_;
    my $plural = $type_plural{$type};
    my $pkg = 'WebService::Async::Desk::' . ($package_name_map{$type} // ucfirst($type));
    {
        my $code = sub {
            my ($self, %args) = @_;

            my $src = $self->new_source;
            my $uri = $self->base_uri->clone;
            $uri->path('/api/v2/' . $plural);
            $self->http_get(
                uri => $uri,
            )->then(sub {
                my ($res) = @_;
                try {
                    $src->emit($_) for map { $pkg->new(desk => $self, %$_) } $res->{_embedded}{entries}->@*;
                    $src->completed->done unless $src->completed->is_ready;
                    Future->done;
                } catch {
                    $log->errorf('Failed - %s', $@);
                    Future->fail($@);
                }
            })->retain;
            return $src;
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

            my %args = @args > 1 ? @args : (id => @args);
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

package WebService::Async::Desk;

use strict;
use warnings;

use parent qw(IO::Async::Notifier);

use Syntax::Keyword::Try;
use Log::Any qw($log);
use URI;
use URI::QueryParam;
use Net::Async::OAuth::Client;
use JSON::MaybeUTF8 qw(:v1);
use Future::AsyncAwait;

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

sub base_uri { shift->{base_uri} //= 'https://desk.com' }

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

sub whatever {
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
    $self->http->do_request(
        request => $req,
    )->then(sub {
        my ($resp) = @_;
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
        $code->($auth_uri);
    }, sub {
        $log->errorf("Failed to do oauth lookup - %s", join ',', @_);
        die @_;
    })->then(sub {
        my ($verify) = @_;
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
        $self->http->do_request(
            request => $req,
        )
    })->then(sub {
        my ($resp) = @_;
        $log->tracef("GetAccessToken response was %s", $resp->as_string("\n"));
        my $rslt = URI->new('http://localhost?' . $resp->decoded_content)->query_form_hash;
        $log->tracef("Extracted token [%s]", $rslt->{oauth_token});
        $self->configure(token => $rslt->{oauth_token});
        $log->tracef("Extracted secret [%s]", $rslt->{oauth_token_secret});
        $self->configure(token_secret => $rslt->{oauth_token_secret});
        Future->done({
            token        => $rslt->{oauth_token},
            token_secret => $rslt->{oauth_token_secret},
        })
    })
}

sub ryu { shift->{ryu} }
sub new_source {
    shift->ryu->new_source
}

async sub company_list {
	my ($self, %args) = @_;

    my $src = $self->new_source;
    my $uri = $self->base_uri->clone;
    $uri->path('/api/v2/companies');
    my ($res) = await $self->http_get(
        uri => $uri,
    );
    $res->{_embedded}{entries}
}

1;

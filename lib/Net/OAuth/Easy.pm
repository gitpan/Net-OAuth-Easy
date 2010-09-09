package Net::OAuth::Easy;
BEGIN {
  $Net::OAuth::Easy::VERSION = '0.001_07';
}
use Moose;
use Digest::MD5 qw{md5_hex};
require Net::OAuth;
require HTTP::Request;

# ABSTRACT: A moose class that abstracts Net::OAuth for you


with qw{
   Net::OAuth::Easy::Roles::Types
};


has ua => (
   is => 'rw',
   isa => 'LWP::UserAgent',
   lazy => 1,
   default => sub{
      require LWP::UserAgent;
      LWP::UserAgent->new;
   },
);


has protocol => (
   is => 'rw',
   isa => 'OAuthProtocol',
   lazy => 1,
   default => sub{'1.0a'},
   trigger => \&set_net_oauth_protocol,
);
sub set_net_oauth_protocol { 
   no warnings;
   $Net::OAuth::PROTOCOL_VERSION = (shift->protocol eq '1.0a') ? &Net::OAuth::PROTOCOL_VERSION_1_0A : &Net::OAuth::PROTOCOL_VERSION_1_0;
}

sub BUILD {
   my $self = shift;
   $self->set_net_oauth_protocol;
}


has $_ => (
   is => 'rw',
   isa => 'Str',
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{ consumer_key consumer_secret };


has $_ => (
   is => 'rw',
   isa => 'ValidURI', 
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{ request_token_url authorize_token_url access_token_url callback };


has request_method => (
   is => 'rw',
   isa => 'RequestMethod',
   default => 'GET',
);


has signature_method => (
   is => 'rw',
   isa => 'SignatureMethod',
   default => 'HMAC-SHA1',
);


has signature_key => (
   is => 'rw',
   isa => 'SignatureKey',
   coerce => 1,
   predicate => 'has_signature_key',
   clearer => 'clear_signature_key',
);


sub timestamp { time };


sub nonce { md5_hex( join '', rand(2**32), time, rand(2**32) ); };


has request_parameters => (
   is => 'rw',
   isa => 'HashRef[ArrayRef]',
   default => sub{{ request_token => [qw{consumer_key 
                                         consumer_secret 
                                         request_url 
                                         request_method 
                                         signature_key 
                                         signature_method 
                                         protocol_version
                                         timestamp 
                                         nonce 
                                         callback 
                                         token
                                         token_secret
                                         verifier
                                        }],
                    access_token  => [qw{consumer_key 
                                         consumer_secret 
                                         request_url 
                                         request_method 
                                         protocol_version
                                         signature_key 
                                         signature_method 
                                         timestamp 
                                         nonce 
                                         token
                                         token_secret
                                         verifier
                                        }],

                    protected_resource => [qw{
                                         consumer_key 
                                         consumer_secret 
                                         request_url 
                                         request_method 
                                         signature_key 
                                         signature_method 
                                         protocol_version
                                         timestamp 
                                         nonce 
                                         token
                                         token_secret
                                        }],
                                         #verifier
   }},
);


has exception_handle => (
   is => 'rw',
   isa => 'CodeRef',
   default => sub{sub{shift;die @_}},
);


sub build_request {
   my $self = shift;
   my $type = shift;
   my $request = Net::OAuth->request($type)->new($self->gather_request_parts($type => @_));

   $self->exception_handle->( q{Unable to sign request} )
      unless $request->sign;

   $self->exception_handle->( q{Unable to verify request} )
      unless $request->verify;

   return $request;
}


sub gather_request_parts {
   my $self = shift;
   my $type = shift;
   my %opts = @_;

   # use type to grab the right url
   my $url_method = sprintf q{%s_url}, $type;
   $opts{request_url} ||= $self->can($url_method) ? $self->$url_method : undef;

   # pull any overrides from %opts/@_ everything else is pulled from $self
   my %req  = map{ $_ => ( exists $opts{$_} ) ? delete $opts{$_} : ( $self->can($_) ) ? $self->$_ : undef;
                 } @{$self->request_parameters->{ $type } || [] };
   # TODO: this is likely not what we really want in cases where you pass Content, NOS builds the URL and then plucks from that, possibly more accurate?
   $req{extra_params} = \%opts if scalar(keys %opts); # save off anything left from @_ as extra params

   $req{protocol_version} = ($self->protocol eq '1.0a') ? &Net::OAuth::PROTOCOL_VERSION_1_0A : &Net::OAuth::PROTOCOL_VERSION_1_0 ;
   
   return %req;
}


has response => (
   is => 'rw',
   isa => 'Object', # TODO: this is too vague
   predicate => 'has_response',
   clearer => 'clear_response',
);


sub content {
   my $self = shift;
   ( $self->has_response ) ? $self->response->content : undef;
}


sub success {
   my $self = shift;
   return ( $self->has_response ) ? $self->response->is_success : 0;
}


sub failure { ! shift->success };


sub error{ 
   my $self = shift;
   return ($self->failure) ? join qq{\n}, map{$self->response->$_} qw{status_line content} : undef;
}


sub make_request {
   my $self = shift;
   my $content;
   # find content if it was passed
   for (my $i=0; $i<scalar(@_); $i++ ) {
      if (defined $_[$i] && $_[$i] =~ m/^Content$/i) {
         $content = delete $_[$i+1];
         delete $_[$i];
         last;
      }
   }
   $self->clear_response if $self->has_response;
   my $request = ( ref($_[0]) && $_[0]->isa('Net::OAuth::Message') ) ? $_[0] : $self->build_request(grep { defined }@_);

   my $req = HTTP::Request->new( $request->request_method => ( $request->request_method eq 'GET' && !$self->include_auth_header_for_GET ) 
                                                           ? $request->to_url 
                                                           : $request->request_url
                               );
   $req->content($content) if defined $content;
   return $self->add_auth_headers($req, $request);
}


has [qw{oauth_header_realm oauth_header_separator}] => (
   is => 'rw',
   isa => 'Maybe[Str]',
);


has include_auth_header_for_GET => (
   is => 'rw',
   isa => 'Bool',
   default => 0,
);

sub build_auth_header {
   my ($self,$oauth_req) = @_;
   $oauth_req->to_authorization_header( 
                                (defined $self->oauth_header_realm) ? $self->oauth_header_realm : undef ,
                                (defined $self->oauth_header_separator) ? $self->oauth_header_separator : undef ,
   );
};


sub add_auth_headers {
   my ($self, $http_req, $oauth_req) = @_;
   $self->exception_handle( 'HTTP::Request expected as first paramater') unless $http_req->isa('HTTP::Request');
   $self->exception_handle( 'Net::OAuth::Message expected as second paramater') unless $oauth_req->isa('Net::OAuth::Message');
   $http_req->authorization( $self->build_auth_header($oauth_req) 
                           ) if $http_req->method eq 'POST' || $self->include_auth_header_for_GET;
   return $http_req;
}


sub send_request {
   my $self = shift;
   my $req = ( ref($_[0]) && $_[0]->isa('HTTP::Request') ) ? $_[0] : $self->make_request(@_);
   $self->response( $self->ua->request( $req ) );
}


has $_ => (
   is => 'rw',
   isa => 'Str',
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{request_token request_token_secret access_token access_token_secret};


sub get_request_token {
   my $self = shift;
   $self->send_request(request_token => @_);
   if ($self->success) {
      my $resp = Net::OAuth->response('request token')->from_post_body($self->response->content);
      $self->request_token( $resp->token );
      $self->request_token_secret( $resp->token_secret );
   }
   return $self->success;
}

   
sub get_authorization_url {
   my $self = shift;
   my %opts = @_;
   $opts{oauth_token} ||= $self->request_token;
   $opts{callback}    ||= $self->callback;
   my $url  = URI->new( $self->authorize_token_url );
   $url->query_form( %opts );
   return $url;
}


sub process_authorization_callback {
   my $self = shift;
   my $url  = (ref($_[0]) eq '') ? URI->new($_[0]) : $_[0]; # if we are handed a string build a uri object of it
   my %opts = $url->query_form;
   for ( grep{! m/^oauth_/} keys %opts ) {
      delete $opts{$_};
   }
   return %opts;
}


has process_access_token_mapping => (
   is => 'rw',
   isa => 'HashRef[ArrayRef]',
   auto_deref => 1,
   default => sub{{ token        => [qw{oauth_token request_token}],
                    token_secret => [qw{request_token_secret}],
                    verifier     => [qw{oauth_verifier}],
                 }},
);


sub process_access_token_input {
   my $self = shift;
   my %opts = @_;
   my %mapp = $self->process_access_token_mapping;
   while ( my ( $key, $map ) = each %mapp ) {
      next if exists $opts{$key}; # dont overwrite anything that was passed to us (respect overwrites)
      for my $lookup ( @$map ) {
         my $value = ( exists $opts{$lookup} ) ? delete $opts{$lookup}
                   : ( $self->can($lookup)   ) ? $self->$lookup
                   :                             undef;  
         $opts{$key} = $value;
         next if $value; # stop looking if we found a value
      }
   }
   return %opts;
}


sub get_access_token {
   my $self = shift;
   my %opts = $self->process_access_token_input( (scalar(@_) == 1) 
                                                ? $self->process_authorization_callback(@_) 
                                                : @_
                                               );

   $self->send_request(access_token => %opts);
   if ($self->success) {
      my $resp = Net::OAuth->response('access token')->from_post_body($self->response->content);
      $self->access_token( $resp->token );
      $self->access_token_secret( $resp->token_secret );
   }
   return $self->success;
}


sub get_protected_resource {
   my $self = shift;
   my %opts = (scalar(@_) == 1) ? (request_url => $_[0]) : @_ ; # allow just the requested URL to be pased
   $opts{token} ||= $self->access_token;
   $opts{token_secret} ||= $self->access_token_secret;
   $self->send_request(protected_resource => %opts);
   return $self->success;
}


1;

__END__
=pod

=head1 NAME

Net::OAuth::Easy - A moose class that abstracts Net::OAuth for you

=head1 VERSION

version 0.001_07

=head1 SYNOPSIS

  use Net::OAuth::Easy;
  my $oauth = Net::OAuth::Easy->new( 
      consumer_key        => $key,
      consumer_secret     => $secret,
      request_token_url   => q{http://someplace.com/request_token},
      authorize_token_url => q{http://someplace.com/authorize},
      access_token_url    => q{http://someplace.com/access_token},
      callback            => q{http://here.com/user},
  );
  $oauth->get_request_token;
  # save off request token secret somewhere, you need it later
  $some_session_idea->request_token_secret($oauth->requset_token_secret);

  my $auth_url   = $oauth->get_authorization_url;
  # redirect user to $auth_url

  ...

  #reload the token secret
  $oauth->request_token_secret( $some_session_idea->request_token_secret );
  $oauth->get_access_token( $q->url );
  #safe off the access tokens now
  $some_storage_idea->access_token($oauth->access_token);
  $some_storage_idea->access_token_secret($oauth->access_token_secret);

  ...

  $oauth->access_token( $some_storage_idea->access_token );
  $oauth->access_token_secret( $some_storage_idea->access_token_secret );
  $oauth->get_protected_resource( $restricted_url )

get_access_token

=head1 DESCRIPTION

=head1 OVERVIEW

=head1 ATTRIBUTES

=head2 ua

A LWP::UserAgent object to do the message passing. 

=head2 protocol

What OAuth protocol do you wish your messages to be build in? 

=over 4

=item * '1.0a' B<Default>

=item * '1.0'

=back

=head2 consumer_key

=head2 consumer_secret

=head2 request_token_url

=head2 authorize_token_url

=head2 access_token_url

=head2 callback

=head2 request_method

Defines the method of the request.

=over 4

=item * 'GET' B<Default>

=item * 'POST'

=back

=head2 signature_method

Defines the method to sign the request.

=over 4

=item * 'HMAC-SHA1' B<Default>

=item * 'RSA-SHA1'

=back

=head2 signature_key

Where to find the signature key, only used for RSA-SHA1 type signatures.

Expected to be passed a Crypt::OpenSSL::RSA object. Though if passed a 
string, this will be assumped to be a filename and will be passed to 
the new_private_key method of Crypt::OpenSSL::RSA. The object that 
results will be stored.

=head2 request_parameters

This is a HashRef of ArrayRefs that is used to define the required
elements of each type of OAuth request. The type (ie request_token)
is the key and all items in the ArrayRef value will be collected 
from $self if not passed at the time that the request is built.

=head2 exception_handle

Stores a coderef that is called when an exception is hit. Out of 
the box this does not do anything more then die with a message, 
though it can be used to leverage diffrent codepaths at the time
of an exception. 

It is used internaly as such:

  $self->exception_handle->(q{unable to sign request});

Thus if you need to define your own you will have $self and a note
about why it was called. 

I'm not completely happy with this so it could change but this should
get any one needing this the most basic items currently.

=head2 response

Stores the response when any of the get_* methods are called.

=head2 oauth_header_realm

If defined it is expected to be a string(URL) that will be included
in to the Authorization headers. If not given it will be ignored.

=head2 oauth_header_separator

A string that denotes the string that you would like to use to 
seperate the key=value pairs in the Authuntication header.

Defaults to ','.

=head2 request_token

Stores the request_token when it's collected via L<get_request_token>.

=head2 request_token_secret

Stores the request_token_secret when it's collected via L<get_request_token>.

=head2 access_token

Stores the access_token when it's collected via L<get_request_token>.

=head2 access_token_secret

Stores the access_token_secret when it's collected via L<get_request_token>.

=head2 process_access_token_mapping

=head1 METHODS

=head2 has_consumer_key

=head2 clear_consumer_key

=head2 has_consumer_secret

=head2 clear_consumer_secret

=head2 has_request_token_url

=head2 clear_request_token_url

=head2 has_authorize_token_url

=head2 clear_authorize_token_url

=head2 has_access_token_url

=head2 clear_access_token_url

=head2 has_callback

=head2 clear_callback

=head2 has_signature_key

=head2 clear_signature_key

=head2 timestamp

Currently just an alias to L<time>, it is used to define the timestamp
of the OAuth request.

=head2 nonce

Define a unique id for every OAuth request, curently this is done by 
taking the md5_hex of two random numbers and the time. 

=head2 build_request

Used to build the Net::OAuth request object based on input and L<gather_request_parts>.

=head2 gather_request_parts

Uses L<request_parameters> to merge passed items with stored values 
to complete all items required for L<build_request>.

=head2 has_response

=head2 clear_response

=head2 content

Shortcut to get the content of the response, will return undef if in
the case of no response yet stored.

=head2 success

Shortcut to see if a successful response was collected, returns 0
in the case of no response yet stored.

=head2 failure

Returns the inverse of L<success>.

=head2 error

In the case of a non-successful response, will return a formated 
string that includes the status_line and content to describe the
reason for failure. Will return undef in the case of no response
yet stored.

=head2 make_request

Given a Net::OAuth request, convert it to a HTTP::Request such 
that it can be sent via L<ua>. One other thing to note is that
make_request also calls clear_request thus destroying any 
previously stored request.

=head2 add_auth_headers

Add the Authentication header to the HTTP request based on the OAuth 
request if the request method is POST.

=head2 send_request

Pass the given HTTP::Request object to L<ua> thus sending out the 
request to the world.

=head2 has_request_token

=head2 clear_request_token

=head2 has_request_token_secret

=head2 clear_request_token_secret

=head2 has_access_token

=head2 clear_access_token

=head2 has_access_token_secret

=head2 clear_access_token_secret

=head2 get_request_token

Builds up an OAuth request to get the request_token pairs.

=head2 get_authorization_url

Build out the URL that is needed to be called to collect the oauth_verifier.

=head2 process_authorization_callback

Unpack the return url from the OAuth provider that includes items
like oauth_verifier. Returns a hash of unparsed items.

=head2 process_access_token_input

=head2 get_access_token

Collect and store the access_tokens.

=head2 get_protected_resource

=roles Net::OAuth::Easy::Roles::Types

=head1 AUTHOR

  Ben Hengst <notbenh@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2010 by Ben Hengst.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut


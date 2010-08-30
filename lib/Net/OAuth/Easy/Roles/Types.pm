package Net::OAuth::Easy::Roles::Types;
BEGIN {
  $Net::OAuth::Easy::Roles::Types::VERSION = '0.001_05';
}
use Moose::Role;
use Moose::Util::TypeConstraints;
use File::Slurp;
use Data::Validate::URI qw(is_uri);
require Crypt::OpenSSL::RSA;

# ABSTRACT: Role to tuck away types into

enum 'OAuthProtocol' => qw(1.0 1.0a);

enum 'RequestMethod' => qw(GET POST);

enum 'SignatureMethod' => qw(HMAC-SHA1 RSA-SHA1);

subtype SignatureKey => as 'Crypt::OpenSSL::RSA';                                                                                                                                  
coerce  SignatureKey =>
     from Str =>
      via { my $file = $_[0];
            die sprintf q{%s does not exist as a readable file}, $file 
               unless -r $file;
            Crypt::OpenSSL::RSA->new_private_key( join '', read_file($file) );
          };

type ValidURI => as Str => where {is_uri($_)};

1;

__END__
=pod

=head1 NAME

Net::OAuth::Easy::Roles::Types - Role to tuck away types into

=head1 VERSION

version 0.001_05

=head1 AUTHOR

  Ben Hengst <notbenh@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2010 by Ben Hengst.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut


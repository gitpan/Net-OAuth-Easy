
use strict;
use warnings;



use ExtUtils::MakeMaker 6.31;



my %WriteMakefileArgs = (
  'ABSTRACT' => 'A moose class that abstracts Net::OAuth for you',
  'AUTHOR' => 'Ben Hengst <notbenh@cpan.org>',
  'BUILD_REQUIRES' => {
    'Carp::Always' => '0',
    'Module::Build' => '0.3601',
    'Test::Most' => '0',
    'Test::WWW::Mechanize' => '0'
  },
  'CONFIGURE_REQUIRES' => {
    'ExtUtils::MakeMaker' => '6.31',
    'Module::Build' => '0.3601'
  },
  'DISTNAME' => 'Net-OAuth-Easy',
  'EXE_FILES' => [],
  'LICENSE' => 'perl',
  'NAME' => 'Net::OAuth::Easy',
  'PREREQ_PM' => {
    'Crypt::OpenSSL::RSA' => '0',
    'Data::Validate::URI' => '0',
    'Digest::MD5' => '0',
    'File::Slurp' => '0',
    'Moose' => '0',
    'Net::OAuth' => '0.27'
  },
  'VERSION' => '0.001_06',
  'test' => {
    'TESTS' => 't/*.t'
  }
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.56) } ) {
  my $br = delete $WriteMakefileArgs{BUILD_REQUIRES};
  my $pp = $WriteMakefileArgs{PREREQ_PM};
  for my $mod ( keys %$br ) {
    if ( exists $pp->{$mod} ) {
      $pp->{$mod} = $br->{$mod} if $br->{$mod} > $pp->{$mod};
    }
    else {
      $pp->{$mod} = $br->{$mod};
    }
  }
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);




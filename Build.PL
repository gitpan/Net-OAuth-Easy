
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  'build_requires' => {
    'Carp::Always' => '0',
    'Module::Build' => '0.3601',
    'Test::Most' => '0',
    'Test::WWW::Mechanize' => '0'
  },
  'configure_requires' => {
    'ExtUtils::MakeMaker' => '6.31',
    'Module::Build' => '0.3601'
  },
  'dist_abstract' => 'A moose class that abstracts Net::OAuth for you',
  'dist_author' => [
    'Ben Hengst <notbenh@cpan.org>'
  ],
  'dist_name' => 'Net-OAuth-Easy',
  'dist_version' => '0.001_07',
  'license' => 'perl',
  'module_name' => 'Net::OAuth::Easy',
  'recommends' => {},
  'recursive_test_files' => 1,
  'requires' => {
    'Crypt::OpenSSL::RSA' => '0',
    'Data::Validate::URI' => '0',
    'Digest::MD5' => '0',
    'File::Slurp' => '0',
    'Moose' => '0',
    'Net::OAuth' => '0.27'
  },
  'script_files' => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;

#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;
use FindBin;
# allows require by filename
use lib "$FindBin::Bin/test_util";

use md4 qw (md4_hex);

sub module_constraints { [[0, 16], [0, 256], [0, 16], [0, 27], [16, 256]] }

sub module_generate_hash
{
  my $pw = shift;
  my $salt = shift;
  my @vector = password_to_vector($pw);
  $salt = $salt ? $salt : random_bytes(32);
  my $digest = md4_hex ($salt,@vector);
  $salt =  unpack 'H*', $salt;
  return $salt.'$'.$digest;
}

sub module_verify_hash
{
  my $line = shift;

  my ($salt_hash, $word) = split (':', $line);
  my ($salt, $hash) = split('\$',$salt_hash);

  return unless defined $hash;
  return unless defined $word;
  return unless defined $salt;

  my $word_packed = pack_if_HEX_notation($word);
  my $salt_packed = pack "H*", $salt;

  my $new_hash = module_generate_hash ($word_packed,$salt_packed);

  return ($new_hash, $word);
}

1;

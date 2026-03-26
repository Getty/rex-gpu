use strict;
use warnings;
use Test::More;

use_ok('Rex::GPU');
use_ok('Rex::GPU::Detect');
use_ok('Rex::GPU::NVIDIA');
use_ok('Rex::Rancher');
use_ok('Rex::Rancher::Node');
use_ok('Rex::Rancher::Server');
use_ok('Rex::Rancher::Agent');
use_ok('Rex::Rancher::Cilium');

done_testing;

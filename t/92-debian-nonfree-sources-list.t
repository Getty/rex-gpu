use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# Unit tests for the classic /etc/apt/sources.list non-free rewrite (karr #40).
#
# The Debian 12 installer writes "deb ... bookworm main non-free-firmware".
# The check this replaces skipped the whole file when it matched /non-free/,
# and non-free-firmware matched, so non-free was never enabled and Debian's
# nvidia-driver had no candidate. _sources_list_enable_nonfree($content) is
# pure (string in, string out), like _deb822_enable_nonfree (t/91).
# Claims asserted:
#   * a Debian archive "deb" line gets exactly the missing ones of contrib,
#     non-free, non-free-firmware appended after its last component;
#   * a second pass changes nothing (idempotent);
#   * every other line -- comments, commented-out deb lines, deb-src,
#     third-party entries -- is kept byte for byte, and an edited line keeps
#     its [options] and trailing # comment;
#   * a line is only edited when it is a Debian archive: components include
#     main, the URI is Debian's (same rules as deb822), signed-by= (if any)
#     names only debian-archive keyrings;
#   * a line the old sed handled ("deb URL suite main") ends up with the same
#     text the sed produced.
#
# NOT covered (needs a real Debian 12 host):
#   * that apt accepts the written file and `apt-cache policy nvidia-driver`
#     then shows a candidate;
#   * the `cat`/`file` round trip over Rex::LibSSH (the command sequence is
#     pinned in t/golden/driver/debian-12--*.txt, not executed).
# -----------------------------------------------------------------------------

use Rex::GPU::NVIDIA;

sub rewrite { [ Rex::GPU::NVIDIA::_sources_list_enable_nonfree($_[0]) ] }

my $ALL = 'contrib non-free non-free-firmware';

# What the bookworm installer writes (netinst, network mirror), cat-chomped.
my $BOOKWORM = <<'SRC';
#deb cdrom:[Debian GNU/Linux 12.11.0 _Bookworm_ - Official amd64 NETINST with firmware 20250517-09:51]/ bookworm contrib main non-free-firmware

deb http://deb.debian.org/debian/ bookworm main non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm main non-free-firmware

deb http://security.debian.org/debian-security bookworm-security main non-free-firmware
deb-src http://security.debian.org/debian-security bookworm-security main non-free-firmware

# bookworm-updates, to get updates before a point release is made;
# see https://www.debian.org/doc/manuals/debian-reference/ch02.en.html#_updates_and_backports
deb http://deb.debian.org/debian/ bookworm-updates main non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm-updates main non-free-firmware
SRC
chomp(my $bookworm_chomped = $BOOKWORM);

(my $BOOKWORM_WANT = $BOOKWORM)
  =~ s/^(deb http\S+ \S+ main non-free-firmware)$/$1 contrib non-free/mg;

subtest 'bookworm installer default: non-free-firmware is not non-free' => sub {
  my ($new, $matched) = @{ rewrite($bookworm_chomped) };
  is($matched, 3, 'three deb lines recognised, deb-src and cdrom comment not');
  is($new, $BOOKWORM_WANT,
    'contrib non-free appended to the deb lines only, final newline restored');
  like($new, qr/^deb http:\/\/security\.debian\.org\/debian-security bookworm-security main non-free-firmware contrib non-free$/m,
    'security line edited');
  is_deeply(rewrite($new), [ undef, 3 ], 'second pass: unchanged, still recognised');
};

subtest 'already fully enabled: no rewrite' => sub {
  my $src = "deb http://deb.debian.org/debian bookworm main $ALL\n"
    . "deb http://security.debian.org/debian-security bookworm-security main $ALL";
  is_deeply(rewrite($src), [ undef, 2 ], 'undef, two lines recognised');
  is(rewrite("deb http://deb.debian.org/debian bookworm non-free main\n")->[0],
    "deb http://deb.debian.org/debian bookworm non-free main contrib non-free-firmware\n",
    'only the missing components are added, existing order kept');
};

subtest 'bullseye main only: same text as the old sed' => sub {
  my @lines = (
    'deb http://deb.debian.org/debian bullseye main',
    'deb http://deb.debian.org/debian bullseye-updates main',
    'deb http://security.debian.org/debian-security bullseye-security main'
  );
  my $src = join("\n", @lines)."\n";
  (my $sed = $src) =~ s/^deb (.*) main/deb $1 main contrib non-free non-free-firmware/mg;
  is_deeply(rewrite($src), [ $sed, 3 ], 'identical to s/^deb \(.*\) main/.../');
  is_deeply(rewrite($sed), [ undef, 3 ], 'idempotent');
};

subtest 'partial components: no duplicate' => sub {
  is(rewrite("deb http://deb.debian.org/debian bookworm main contrib\n")->[0],
    "deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware\n",
    'contrib not repeated (the old sed would have produced main contrib non-free non-free-firmware contrib)');
};

subtest 'options in brackets, spacing and trailing comments kept' => sub {
  my %case = (
    'signed-by debian-archive keyring' => [
      'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian bookworm main',
      'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian bookworm main '.$ALL
    ],
    'arch option with spaces inside brackets' => [
      'deb [ arch=amd64,arm64 ] http://deb.debian.org/debian bookworm main non-free-firmware',
      'deb [ arch=amd64,arm64 ] http://deb.debian.org/debian bookworm main non-free-firmware contrib non-free'
    ],
    'tabs and trailing comment' => [
      "deb\thttp://mirror.hetzner.com/debian/packages\tbookworm\tmain   # Hetzner",
      "deb\thttp://mirror.hetzner.com/debian/packages\tbookworm\tmain $ALL   # Hetzner"
    ],
    'CRLF line ending' => [
      "deb http://deb.debian.org/debian bookworm main\r",
      "deb http://deb.debian.org/debian bookworm main $ALL\r"
    ],
    'cloud image mirror+file' => [
      'deb mirror+file:/etc/apt/mirrors/debian.list bookworm main',
      'deb mirror+file:/etc/apt/mirrors/debian.list bookworm main '.$ALL
    ]
  );
  for my $name (sort keys %case) {
    my ($in, $want) = @{ $case{$name} };
    is_deeply(rewrite("$in\n"), [ "$want\n", 1 ], $name);
  }
};

subtest 'third-party, commented, deb-src and non-matching lines are left alone' => sub {
  my %case = (
    'third party with main' =>
      'deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com bookworm main',
    'third party with main, no options' =>
      'deb https://packages.microsoft.com/debian/12/prod bookworm main',
    'Docker (Debian path, no main)' =>
      'deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable',
    'NVIDIA flat repo' =>
      'deb [signed-by=/usr/share/keyrings/cuda-archive-keyring.gpg] https://developer.download.nvidia.com/compute/cuda/repos/debian12/x86_64/ /',
    'Debian URI but foreign key' =>
      'deb [signed-by=/etc/apt/keyrings/other.gpg] http://deb.debian.org/debian bookworm main',
    'Debian URI, one of two keys foreign' =>
      'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg,/etc/apt/keyrings/other.gpg] http://deb.debian.org/debian bookworm main',
    'lookalike host' =>
      'deb http://deb.debian.org.example.com/debian bookworm main',
    'Hetzner host outside /debian/' =>
      'deb http://mirror.hetzner.com/ubuntu/packages noble main',
    'unknown Debian mirror' =>
      'deb http://ftp.fau.de/debian bookworm main',
    'commented out' =>
      '# deb http://deb.debian.org/debian bookworm main',
    'commented out, no space' =>
      '#deb http://deb.debian.org/debian bookworm main',
    'deb-src' =>
      'deb-src http://deb.debian.org/debian bookworm main',
    'cdrom' =>
      'deb cdrom:[Debian GNU/Linux 12.11.0 _Bookworm_]/ bookworm main non-free-firmware',
    'main only in a comment' =>
      'deb http://deb.debian.org/debian bookworm # main'
  );
  for my $name (sort keys %case) {
    is_deeply(rewrite("$case{$name}\n"), [ undef, 0 ], $name);
  }

  my $mixed = $BOOKWORM . $case{'third party with main'} . "\n";
  my ($new, $matched) = @{ rewrite($mixed) };
  is($matched, 3, 'Debian + third party in one file: three recognised');
  is($new, $BOOKWORM_WANT . $case{'third party with main'} . "\n",
    'only the Debian deb lines edited');
};

subtest 'empty and comment-only input' => sub {
  is_deeply(rewrite(''), [ undef, 0 ], 'empty string');
  is_deeply(rewrite(undef), [ undef, 0 ], 'undef');
  is_deeply(rewrite("# See sources.list(5) and debian.sources\n"), [ undef, 0 ],
    'comment-only file (deb822 host)');
};

done_testing;

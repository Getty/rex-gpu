# ABSTRACT: NVIDIA driver setup for Debian (experimental)

package Rex::GPU::NVIDIA::Setup::Debian;
our $VERSION = '0.002';
use Moo;
use Rex::Logger ();
use namespace::autoclean;

extends 'Rex::GPU::NVIDIA::Setup::Apt';

=method sources

In this order:

=over

=item * C<debian-nonfree> -- C<nvidia-driver> + C<nvidia-smi> +
C<libcuda1> from Debian C<non-free>, proprietary kernel module, verified by
C<nvidia-driver> and C<libcuda1>. C<libcuda1> is named because
C<nvidia-driver> pulls it only through recommends
(C<libnvidia-encode1> -E<gt> C<libnvcuvid1>), so a host with
C<APT::Install-Recommends "false"> would get no CUDA library -- and without
it L<Rex::GPU::NVIDIA::Setup/already_installed> never counts the driver as
installed. Its branch comes from L</nonfree_branch>; on a release that table
does not know it is unknown, which fits only a GPU without constraints.

=item * C<nvidia-cuda-repo> -- NVIDIA's CUDA apt repository for C<debian12>
or C<debian13> (C<x86_64> for amd64, C<sbsa> for arm64, key C<cuda_repo>):
the compute-only open-module set C<nvidia-driver-cuda> +
C<nvidia-kernel-open-dkms>, both verified, the newest branch the repository
carries, at least 590. Unavailable on any other release or architecture.

=back

So a Blackwell GPU (open module, 570 or newer: no Debian-packaged driver
fits) gets the CUDA repository on Debian 12/13 and dies before the host is
changed anywhere else; every other GPU gets C<non-free>.

=method nonfree_branch

  my $branch = $self->nonfree_branch($major);   # 12 => 535

The driver branch of Debian's own C<nvidia-driver> in a release: 11 (470),
12 (535), 13 (550); C<undef> for any other. A fixed table (maintainer
decision, epic karr #25): looking it up with C<apt-cache> would need
C<non-free> enabled first, a host change before the plan can fail.
Override it for a release this table does not know.

=cut

# nvidia-graphics-drivers per suite, sources.debian.org/api/src/
# nvidia-graphics-drivers/ checked 2026-09-23: bullseye 470.256.02,
# bookworm 535.261.03, trixie 550.163.01. forky/sid (550 today) is
# deliberately absent: it moves.
sub nonfree_branch {
  my ( $self, $major ) = @_;
  my %branch = ( 11 => 470, 12 => 535, 13 => 550 );
  return $branch{ $major // 0 };
}

sub sources {
  my ( $self ) = @_;
  my $major = $self->_major_version($self->release);
  return (
    {
      name          => 'debian-nonfree',
      kernel_module => 'proprietary',
      branch        => $self->nonfree_branch($major),
      # libcuda1 explicitly (karr #42): only a recommends of nvidia-driver
      # (via libnvidia-encode1 -> libnvcuvid1), and already_installed needs it
      packages      => [ 'nvidia-driver', 'nvidia-smi', 'libcuda1' ],
      verify        => [ 'nvidia-driver', 'libcuda1' ],
      nonfree       => 1
    },
    $self->_cuda_repo_source($major)
  );
}

# Debian + Blackwell (karr #18): no Debian-packaged driver supports Blackwell
# (bookworm 535, trixie/sid 550; Blackwell needs >= 570 AND the open kernel
# module), so it comes from NVIDIA's CUDA apt repo. Falling back to Debian
# non-free where NVIDIA has no repo would install a driver that dpkg reports
# as ii but whose module never binds; guessing a neighbouring repo would mix
# a foreign distro's libc/dkms into the host -- so that source is simply
# unavailable there.
#
# branch_at_least 590: the branch every tree carries. Checked 2026-09-23 in
# the repos' Packages.gz (nvidia-kernel-open-dkms): debian12/x86_64 545..615,
# debian12/sbsa 590..615, debian13/x86_64 590..615, debian13/sbsa 595..615.
# The repo installs its newest branch, which is at least that.
#
# NOT nvidia-driver in verify: that name exists in Debian non-free too, so a
# leftover Debian 535/550 install would pass it. nvidia-kernel-open-dkms
# exists only in NVIDIA's repo.
sub _cuda_repo_source {
  my ( $self, $major ) = @_;
  my $packages = [ 'nvidia-driver-cuda', 'nvidia-kernel-open-dkms' ];
  my %source = (
    name            => 'nvidia-cuda-repo',
    kernel_module   => 'open',
    branch_at_least => 590,
    packages        => $packages,
    verify          => [ @$packages ]
  );
  my $release = $self->release // '';
  my $arch    = $self->arch // '';
  if ($major != 12 && $major != 13) {
    $source{unavailable} = "NVIDIA's CUDA repo only covers Debian 12 and 13, not release '$release'";
  }
  elsif ($arch ne 'amd64' && $arch ne 'arm64') {
    $source{unavailable} = "NVIDIA's CUDA repo only covers amd64 and arm64, not '$arch'";
  }
  else {
    my $distro    = "debian$major";
    my $repo_arch = $self->_cuda_repo_arch($arch);   # arm64 -> sbsa, amd64 -> x86_64
    $source{cuda_repo} = {
      distro      => $distro,
      arch        => $repo_arch,
      keyring_url => "https://developer.download.nvidia.com/compute/cuda/repos/$distro/$repo_arch/cuda-keyring_1.1-1_all.deb"
    };
  }
  return \%source;
}

=method plan

The base plan, plus C<< $plan->{cuda_repo} >>: the chosen source's CUDA
repository, or C<undef> on the C<non-free> path.

=cut

sub plan {
  my ( $self ) = @_;
  my $plan = $self->SUPER::plan;
  $plan->{cuda_repo} = $plan->{source} && $plan->{source}{cuda_repo};
  return $plan;
}

=method prepare_host

Enables C<contrib non-free non-free-firmware> in Debian's own archive entries
(L</enable_nonfree>) when the chosen source is C<non-free> -- not on the
CUDA-repo path, whose packages resolve from NVIDIA's repo plus Debian
C<main>, and must not mix with Debian's nvidia packages -- then the apt
layer's step.

=cut

sub prepare_host {
  my ( $self, $plan ) = @_;
  $self->enable_nonfree if $plan->{source} && $plan->{source}{nonfree};
  $self->SUPER::prepare_host($plan);
}

=method prepare_source

On the CUDA-repo path registers NVIDIA's repository
(L</add_nvidia_cuda_apt_repo>) before the apt layer's C<apt-get update>.

=cut

sub prepare_source {
  my ( $self, $plan ) = @_;
  $self->add_nvidia_cuda_apt_repo($plan->{cuda_repo}) if $plan->{cuda_repo};
  $self->SUPER::prepare_source($plan);
}

=method add_nvidia_cuda_apt_repo

  $self->add_nvidia_cuda_apt_repo($repo);

Installs the C<cuda-keyring> package of C<$repo> (signing key plus the
sources.list.d entry) with C<apt-get>, and dies unless it is C<ii>
afterwards -- without it the driver install could only fail with a misleading
"unable to locate package".

=cut

sub add_nvidia_cuda_apt_repo {
  my ( $self, $repo ) = @_;
  Rex::Logger::info("  Adding NVIDIA CUDA repo ($repo->{distro}/$repo->{arch})...");
  # curl is an inert helper, so pkg is fine for it
  $self->pkg_cmd(["curl"], ensure => "present");
  $self->run_cmd(q{t=$(mktemp -d) && curl -fsSL -o "$t/cuda-keyring.deb" }
    . $repo->{keyring_url}
    . q{ && DEBIAN_FRONTEND=noninteractive }.$self->apt_get.q{ install -y "$t/cuda-keyring.deb"; rm -rf "$t"},
    auto_die => 0);
  my $check = $self->run_cmd("dpkg -l cuda-keyring 2>/dev/null | grep -q '^ii'", auto_die => 0);
  die "cuda-keyring not installed — cannot add NVIDIA's CUDA repo ($repo->{keyring_url})\n"
    if $? != 0;
}

=method enable_nonfree

Adds whichever of C<contrib>, C<non-free>, C<non-free-firmware> is missing to
every recognised Debian archive entry, in C</etc/apt/sources.list> first and
then in the deb822 C</etc/apt/sources.list.d/*.sources> (both may be present).
Third-party entries and unknown mirrors are left alone; a file with nothing
to add is not rewritten. Warns if no Debian archive entry is recognised.

=cut

sub enable_nonfree {
  my ( $self ) = @_;
  my $classic = $self->_enable_nonfree_sources_list;
  my $deb822  = $self->_enable_nonfree_deb822;
  Rex::Logger::info("  No Debian archive entry recognised in /etc/apt/sources.list or "
    . "/etc/apt/sources.list.d/*.sources — non-free was not enabled, Debian's "
    . "nvidia-driver may have no installation candidate", 'warn')
    unless $classic || $deb822;
}

# Classic one-line format, /etc/apt/sources.list (karr #40): read with cat,
# the edit computed in Perl (_sources_list_enable_nonfree, pure) and a changed
# file written back with `file`. Returns the number of Debian archive "deb"
# lines recognised (edited or already complete); 0 for a missing, empty or
# comment-only file.
sub _enable_nonfree_sources_list {
  my ( $self ) = @_;
  my $path    = '/etc/apt/sources.list';
  my $content = $self->run_cmd("cat $path 2>/dev/null", auto_die => 0);
  return 0 if $? != 0 || !defined $content || $content eq '';
  my ($new, $matched) = $self->_sources_list_enable_nonfree($content);
  if (defined $new) {
    Rex::Logger::info("  Enabling non-free repos for NVIDIA drivers ($path)");
    $self->file_cmd($path, content => $new, mode => 644);
  }
  return $matched;
}

# Pure (karr #40): add the components contrib non-free non-free-firmware --
# only those missing, after the last component -- to every one-line "deb"
# entry that is a Debian archive. $content is sources.list as `cat` returns
# it (last newline chomped). Returns ($new_content, $matched): $new_content
# undef when nothing changed (idempotent), $matched the Debian archive lines
# seen. Every other line -- comments, deb-src, third-party entries,
# unparseable lines -- is kept byte for byte; an edited line keeps its
# options, spacing and trailing # comment.
#
# A line is a Debian archive -- and edited -- only if ALL of:
#   * it is an active "deb" line (not "deb-src", not commented out), in the
#     form  deb [ options ] URI suite component...  (options optional);
#   * its components include "main";
#   * its URI is Debian's (_debian_archive_uri: the same rules as deb822);
#   * a signed-by= option, if present, names only debian-archive-* keyrings.
# The Debian 12 installer writes "deb ... bookworm main non-free-firmware":
# non-free-firmware is not non-free.
sub _sources_list_enable_nonfree {
  my ( $self, $content ) = @_;
  return (undef, 0) unless defined $content && length $content;

  my @lines = split /^/m, $content;
  $lines[-1] .= "\n" unless $lines[-1] =~ /\n\z/;

  my ($changed, $matched) = (0, 0);
  for my $line (@lines) {
    my ($body, $eol) = $line =~ /\A(.*?)(\r?\n)\z/s;
    next unless $body =~ /\A[ \t]*deb[ \t]+
      (?:\[([^\]]*)\][ \t]*)?            # 1: options
      (\S+)[ \t]+(\S+)                   # 2: URI  3: suite
      ((?:[ \t]+[^\s\#]+)*)              # 4: components
      ([ \t]*(?:\#.*)?)\z                 # 5: trailing space, comment
    /x;
    my ($opts, $uri, $comps, $rest) = ($1 // '', $2, $4, $5);
    my @comps = split ' ', $comps;
    next unless grep { $_ eq 'main' } @comps;
    next unless $self->_debian_archive_uri($uri);
    my @signed_by = map { /^signed-by=(.*)$/i ? ($1) : () } split ' ', $opts;
    next if @signed_by && !$self->_debian_archive_keyring(map { split /,/ } @signed_by);
    $matched++;

    my %have    = map { $_ => 1 } @comps;
    my @missing = grep { !$have{$_} } qw( contrib non-free non-free-firmware );
    next unless @missing;
    my $head = substr($body, 0, length($body) - length($rest));
    $line = $head.' '.join(' ', @missing).$rest.$eol;
    $changed++;
  }
  return ($changed ? join('', @lines) : undef, $matched);
}

# deb822 format (karr #36): /etc/apt/sources.list.d/*.sources, the default on
# Debian 13 and on Debian's cloud images (debian.sources). Files are read with
# cat, the edit is computed in Perl (_deb822_enable_nonfree, pure) and a
# changed file is written back with `file` -- exec-channel only under
# Rex::LibSSH, no SFTP. Only names apt itself reads are considered (letters,
# digits, _ . - ending in .sources), which also keeps them shell-safe.
# Returns the number of Debian archive stanzas recognised.
sub _enable_nonfree_deb822 {
  my ( $self ) = @_;
  my $dir = '/etc/apt/sources.list.d';
  my @names = grep { /^[A-Za-z0-9_.-]+\.sources$/ }
    split /\n/, ($self->run_cmd("ls -1 $dir/ 2>/dev/null", auto_die => 0)) // '';

  my $recognised = 0;
  for my $name (@names) {
    my $path    = "$dir/$name";
    my $content = $self->run_cmd("cat $path 2>/dev/null", auto_die => 0);
    next if $? != 0 || !defined $content || $content eq '';
    my ($new, $matched) = $self->_deb822_enable_nonfree($content);
    $recognised += $matched;
    next unless defined $new;
    Rex::Logger::info("  Enabling non-free repos for NVIDIA drivers ($path)");
    $self->file_cmd($path, content => $new, mode => 644);
  }
  return $recognised;
}

# Pure (karr #36): add the components contrib non-free non-free-firmware --
# only those missing -- to the Components: field of every deb822 stanza that
# is a Debian archive. Returns ($new_content, $matched) like
# _sources_list_enable_nonfree. Every line not rewritten is kept byte for
# byte, comments included.
#
# A stanza is a Debian archive -- and edited -- only if ALL of:
#   * Types: lists "deb", and Enabled: is not "no";
#   * Components: lists "main";
#   * every URIs: entry is Debian's (_debian_archive_uri);
#   * Signed-By:, if present, names a debian-archive-* keyring file under
#     /usr/share/keyrings.
# Suites are deliberately not matched against codenames. An unknown mirror is
# NOT edited: the caller then warns, and the driver install dies at its dpkg
# check, rather than this editing a repository it cannot identify.
sub _deb822_enable_nonfree {
  my ( $self, $content ) = @_;
  return (undef, 0) unless defined $content && length $content;

  my @lines = split /^/m, $content;
  $lines[-1] .= "\n" unless $lines[-1] =~ /\n\z/;

  # Stanzas: runs of lines separated by blank lines. Per stanza, per field
  # (lower-cased name): its value and the index of its last line.
  my (@stanzas, $cur, $field);
  for my $i (0 .. $#lines) {
    my $l = $lines[$i];
    if ($l =~ /^\s*$/) { undef $cur; undef $field; next }
    unless ($cur) { $cur = {}; push @stanzas, $cur }
    next if $l =~ /^#/;
    if ($l =~ /^([A-Za-z0-9][A-Za-z0-9_-]*):[ \t]*(.*?)\s*$/) {
      $field = lc $1;
      $cur->{$field} = { value => $2, last => $i };
    }
    elsif ($field && $l =~ /^[ \t]+(.*?)\s*$/) {
      $cur->{$field}{value} .= ' '.$1;
      $cur->{$field}{last}   = $i;
    }
  }

  my ($changed, $matched) = (0, 0);
  for my $s (@stanzas) {
    next unless $self->_deb822_is_debian_archive($s);
    $matched++;
    my %have    = map { $_ => 1 } split ' ', $s->{components}{value};
    my @missing = grep { !$have{$_} } qw( contrib non-free non-free-firmware );
    next unless @missing;
    my $i = $s->{components}{last};
    $lines[$i] =~ s/[ \t]*(\r?\n)\z/' '.join(' ', @missing).$1/e;
    $changed++;
  }
  return ($changed ? join('', @lines) : undef, $matched);
}

sub _deb822_is_debian_archive {
  my ( $self, $s ) = @_;
  my $tokens = sub { my $f = $s->{$_[0]}; $f ? split(' ', $f->{value}) : () };

  return 0 unless grep { $_ eq 'deb' } $tokens->('types');
  return 0 if $s->{enabled} && lc $s->{enabled}{value} eq 'no';
  return 0 unless grep { $_ eq 'main' } $tokens->('components');

  my @uris = $tokens->('uris');
  return 0 unless @uris;
  for my $uri (@uris) {
    return 0 unless $self->_debian_archive_uri($uri);
  }

  return 0 if $s->{'signed-by'}
    && !$self->_debian_archive_keyring(split /[\s,]+/, $s->{'signed-by'}{value});
  return 1;
}

# Shared by both formats (karr #36, #40): is $uri one of Debian's archives --
# a host *.debian.org, Hetzner's Debian mirror (mirror.hetzner.com|de under
# /debian/), or the mirror+file:/etc/apt/mirrors/debian[-security].list
# indirection of Debian's cloud images? An unknown mirror is not.
sub _debian_archive_uri {
  my ( $self, $uri ) = @_;
  return 1 if $uri =~ m{^mirror\+file:(?://)?/etc/apt/mirrors/debian(?:-security)?\.list$};
  return 0 unless $uri =~ m{^(?:[a-z0-9]+\+)?(?:https?|ftp)://([^/:\s]+)(?::\d+)?(/\S*)?$}i;
  my ($host, $path) = (lc $1, $2 // '/');
  return 1 if $host eq 'debian.org' || $host =~ /\.debian\.org$/;
  return 1 if $host =~ /^mirror\.hetzner\.(?:com|de)$/ && $path =~ m{^/debian/};
  return 0;
}

# Shared by both formats: true if a Signed-By / signed-by= value names at
# least one key and every key is a debian-archive-* keyring file under
# /usr/share/keyrings (an inline key or any other keyring means a third-party
# repo).
sub _debian_archive_keyring {
  my ( $self, @keys ) = @_;
  @keys = grep { length } @keys;
  return 0 unless @keys;
  for my $key (@keys) {
    return 0 unless $key =~ m{^/usr/share/keyrings/debian-archive-[A-Za-z0-9_.-]+\.(?:gpg|pgp|asc)$};
  }
  return 1;
}

1;

=head1 DESCRIPTION

B<Experimental>, like L<Rex::GPU::NVIDIA::Setup>. The NVIDIA driver install
for Debian (and every C<is_debian> host that is not Ubuntu): C<nvidia-driver>
from Debian C<non-free>, or where that cannot drive the GPUs (Blackwell) the
open-module set from NVIDIA's CUDA repository (L</sources>), on the apt
layer L<Rex::GPU::NVIDIA::Setup::Apt>.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA::Setup>, L<Rex::GPU::NVIDIA/install_driver>

=cut

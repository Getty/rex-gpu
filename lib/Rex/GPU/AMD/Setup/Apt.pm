# ABSTRACT: apt/dpkg packaging layer of the AMD driver setups, and the ROCm install (experimental)

package Rex::GPU::AMD::Setup::Apt;
our $VERSION = '0.006';
use Moo;
use Rex::Logger ();
use namespace::autoclean;

extends 'Rex::GPU::AMD::Setup';

=attr apt_lock_timeout

Seconds C<apt-get> waits for the dpkg lock (C<-o DPkg::Lock::Timeout=>).
Default C<120>: on a fresh boot cloud-init and unattended-upgrades still
hold it.

=cut

has apt_lock_timeout => ( is => 'ro', default => 120 );

sub _build_arch {
  my ( $self ) = @_;
  my $arch = $self->run_cmd('dpkg --print-architecture') // '';
  $arch =~ s/\s+//g;
  return $arch;
}

sub supported_arch { 'amd64' }

=method apt_get

C<apt-get -o DPkg::Lock::Timeout=120>: every C<apt-get> of this layer.

=method prepare_host

Stops C<unattended-upgrades>, C<apt-daily> and C<apt-daily-upgrade>
(on a fresh boot they hold the dpkg lock).

=method refresh_index

C<apt-get update -q>, C<auto_die =E<gt> 0>: it exits non-zero on warnings
that are no failure; a missing package shows in the next step.

=method has_candidate

C<LC_ALL=C apt-cache policy PKG> lists a C<Candidate> other than
C<(none)> -- an installed package is its own candidate, also when no
source carries it any more. Read-only.

=method package_installed

C<dpkg -l PKG | grep -q '^[hi]i'>: installed and configured, held (C<hi>)
or not (C<ii>). Read-only.

=method package_on_disk

C<dpkg-query -W -f='${Status}\n' PKG>: true when dpkg knows the package in
any state but C<not-installed> and C<config-files> -- unlike
L</package_installed>, held, unpacked, half-configured and half-installed
count too. Read-only.

=method install_helpers

C<curl> and C<gpg>, only if C<command -v> does not find them: after an
L</refresh_index>, C<apt-get install --no-upgrade curl gnupg>, verified.

=method install_packages

  $setup->install_packages($plan);

C<DEBIAN_FRONTEND=noninteractive apt-get install -y> of the plan's
packages, directly: never L<Rex::Commands::Pkg>.

=method verify_packages

Each of the plan's packages must be L</package_installed>, C<ii> or C<hi>
in C<dpkg -l>; dies otherwise. A failed DKMS build makes C<amdgpu-dkms>'s
post-install exit non-zero, which leaves it half-configured -- C<iF> (C<hF>
when held), not C<ii> or C<hi>.

=cut

sub apt_get {
  my ( $self ) = @_;
  return 'apt-get -o DPkg::Lock::Timeout='.$self->apt_lock_timeout;
}

sub prepare_host {
  my ( $self ) = @_;
  $self->run_cmd('systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true');
  return;
}

sub refresh_index {
  my ( $self ) = @_;
  $self->run_cmd($self->apt_get.' update -q');
  return;
}

sub has_candidate {
  my ( $self, $package ) = @_;
  my $out = $self->run_cmd("LC_ALL=C apt-cache policy $package 2>/dev/null") // '';
  return $out =~ /^\s*Candidate:\s*(\S+)/m && $1 ne '(none)' ? 1 : 0;
}

sub package_installed {
  my ( $self, $package ) = @_;
  $self->run_cmd("dpkg -l $package 2>/dev/null | grep -q '^[hi]i'");
  return $? == 0 ? 1 : 0;
}

# ${Status} is "WANT EFLAG STATUS" (hold ok installed, install reinstreq
# half-installed, ...); a package dpkg never had prints nothing.
sub package_on_disk {
  my ( $self, $package ) = @_;
  my $out = $self->run_cmd(q{dpkg-query -W -f='${Status}\n' }.$package.' 2>/dev/null') // '';
  return ( grep { /\A\S+ \S+ (\S+)\s*\z/ && $1 ne 'not-installed' && $1 ne 'config-files' }
    split /\r?\n/, $out ) ? 1 : 0;
}

sub install_helpers {
  my ( $self ) = @_;
  my @missing;
  for my $helper ([ curl => 'curl' ], [ gpg => 'gnupg' ]) {
    $self->run_cmd("command -v $helper->[0] >/dev/null 2>&1");
    push @missing, $helper->[1] if $? != 0;
  }
  return unless @missing;
  $self->refresh_index;
  $self->run_cmd('DEBIAN_FRONTEND=noninteractive '.$self->apt_get.' install -y --no-upgrade '
    .join(' ', @missing));
  $self->verify_packages({ packages => \@missing });
  return;
}

sub install_packages {
  my ( $self, $plan ) = @_;
  Rex::Logger::info('  Installing: '.join(', ', @{ $plan->{packages} }));
  $self->run_cmd('DEBIAN_FRONTEND=noninteractive '.$self->apt_get.' install -y '
    .join(' ', @{ $plan->{packages} }));
  return;
}

sub verify_packages {
  my ( $self, $plan ) = @_;
  for my $package (@{ $plan->{packages} }) {
    next if $self->package_installed($package);
    die "$package not installed after apt-get install -- check the apt output"
      .( $package eq 'amdgpu-dkms'
         ? '; a failed DKMS build leaves it half-configured (/var/lib/dkms/amdgpu/*/build/make.log)'
         : '' )."\n";
  }
  return;
}

=method dkms_suite

The C<repo.radeon.com/amdgpu/31.60/ubuntu> suite for this release
(C<resolute>, C<noble>, C<jammy>), C<undef> where AMD has none. Per OS
class.

=method dkms_repo

C</etc/apt/sources.list.d/amdgpu.list> with AMD's line,
C<deb [arch=amd64 signed-by=/etc/apt/keyrings/rocm.gpg]
https://repo.radeon.com/amdgpu/31.60/ubuntu SUITE main>.

=cut

sub dkms_suite { return }

sub dkms_repo {
  my ( $self ) = @_;
  my $key = $self->amdgpu_key;
  return {
    file    => '/etc/apt/sources.list.d/amdgpu.list',
    content => 'deb [arch=amd64 signed-by='.$key->{path}.'] https://repo.radeon.com/amdgpu/'
      .$self->amdgpu_release.'/ubuntu '.( $self->dkms_suite // 'unknown' )." main\n",
    key     => $key,
  };
}

=method place_key

C<gpg --dearmor> of the checked key into C<path>, through a temporary file
that replaces it only when non-empty, mode 0644 for
apt's C<_apt> user.

=cut

sub place_key {
  my ( $self, $dir, $path ) = @_;
  $self->run_cmd("GNUPGHOME=$dir gpg --batch --yes --dearmor -o $dir/key.gpg $dir/key.asc "
    ."&& test -s $dir/key.gpg && chmod 0644 $dir/key.gpg && mv -f $dir/key.gpg $path");
  return $? == 0 ? 1 : 0;
}

=method install_rocm

  my $how = $setup->install_rocm($rocm, \@targets);   # 'present' or 'installed'

Host-read-only first: L</rocm_repo_dir> (dies without one), C<amd64>,
C<dpkg-query> of C<rocm-core> (in any state but C<not-installed> and
C<config-files>, as L</package_on_disk> counts -- held, unpacked and
half-configured too: dies; AMD requires removing the old ROCm line first,
and this never uninstalls) and of the target packages (all installed and
configured, held or not, at the release: C<present>; an unpacked or
half-configured one is not), the existing
C</etc/apt/sources.list.d/amdrocm-stable.sources> (other content: dies).
Then L</prepare_host>, L</install_helpers>, the key to
C</etc/apt/keyrings/amdrocm.gpg> (L<Rex::GPU::AMD::Setup/install_key>),
the deb822 source AMD documents, L</refresh_index>, C<apt-get install> of
the extra and target packages, and every one must pass
L</verify_packages> and be installed at the release.

=cut

sub install_rocm {
  my ( $self, $rocm, $targets ) = @_;
  my $release = $rocm->{release};
  my $dir = $self->rocm_repo_dir
    or die "install_rocm: AMD has no ROCm $release repository for ".$self->os_label
      .". Nothing was changed on the host\n";
  die "install_rocm: ROCm $release is built for amd64 only; this host is ".$self->arch
    .". Nothing was changed on the host\n"
    unless $self->arch eq 'amd64';
  my @packages = map { $rocm->{package_prefix}.$_ } @$targets;
  my $status = $self->_dpkg_status('rocm-core', @packages);
  my $old = $status->{'rocm-core'};
  if (_on_disk($old)) {
    die "install_rocm: ROCm ".( $old->{version} // 'of unknown version' )." (rocm-core) is "
      ."$old->{state}; AMD requires removing ROCm 7.2.4 or older before installing ROCm $release, "
      ."and install_rocm does not uninstall. Nothing was changed on the host\n";
  }
  my $at_release = sub { my ( $s ) = @_; _installed($s) && index($s->{version}, "$release.") == 0 };
  unless (grep { !$at_release->($status->{$_}) } @packages) {
    Rex::Logger::info("ROCm $release already installed: ".join(', ', @packages));
    return 'present';
  }

  my $key = { url => $rocm->{key_url}, fingerprint => $rocm->{key_fingerprint},
              path => '/etc/apt/keyrings/amdrocm.gpg' };
  my $file = '/etc/apt/sources.list.d/amdrocm-stable.sources';
  my $content = join "\n",
    'X-Repo-Id: amdrocm-stable',
    'Types: deb',
    'URIs: '.$rocm->{repo_url}.$dir.'/',
    'Suites: stable',
    'Components: main',
    'Architectures: amd64',
    'Signed-By: '.$key->{path},
    'Enabled: yes', '';
  my $current = $self->file_content($file);
  die "install_rocm: $file exists with other content than ROCm $release needs; install_rocm "
    ."does not replace a repository it did not write. Nothing was changed on the host\n"
    if length $current && _trim($current) ne _trim($content);

  $self->prepare_host;
  $self->install_helpers;
  $self->install_key(%$key);
  $self->write_file($file, $content) unless length $current;
  $self->refresh_index;
  my $plan = { packages => [ @{ $rocm->{extra_packages} || [] }, @packages ] };
  $self->install_packages($plan);
  $self->verify_packages($plan);
  $status = $self->_dpkg_status(@packages);
  for my $package (@packages) {
    die "install_rocm: $package is installed at ".( $status->{$package}{version} // 'no version' )
      .", not ROCm $release\n"
      unless $at_release->($status->{$package});
  }
  Rex::Logger::info("ROCm $release installed for ".join(', ', @$targets));
  return 'installed';
}

# { package => { status => 'WANT EFLAG STATE', state => STATE, version => ... } }
# for every one of @packages dpkg has a record of, in any state (k89: the
# rocm-core check and the present check count them differently); version is
# undef for not-installed. Read-only.
sub _dpkg_status {
  my ( $self, @packages ) = @_;
  my $out = $self->run_cmd(q{dpkg-query -W -f='${Package} ${Status} ${Version}\n' }
    .join(' ', @packages).' 2>/dev/null') // '';
  my %status;
  for my $line (split /\r?\n/, $out) {
    next unless $line =~ /\A(\S+) (\S+ \S+ (\S+))(?: (\S+))?\s*\z/;
    # one line per architecture dpkg has a record for: a record on disk is
    # never replaced by one that is not
    next if _on_disk($status{$1});
    $status{$1} = { status => $2, state => $3, version => $4 };
  }
  return \%status;
}

# On disk in any state but not-installed and config-files, as package_on_disk
# counts (k89).
sub _on_disk {
  my ( $s ) = @_;
  return $s && $s->{state} ne 'not-installed' && $s->{state} ne 'config-files' ? 1 : 0;
}

# Installed and configured, held or not (k89).
sub _installed {
  my ( $s ) = @_;
  return $s && $s->{status} =~ /\A(?:install|hold) ok installed\z/ ? 1 : 0;
}

sub _trim {
  my ( $text ) = @_;
  $text //= '';
  $text =~ s/\A\s+|\s+\z//g;
  return $text;
}

1;

=head1 DESCRIPTION

B<Experimental.> The apt/dpkg layer under L<Rex::GPU::AMD::Setup::Ubuntu>
and L<Rex::GPU::AMD::Setup::Debian>, with the driver path's apt rules
(as in L<Rex::GPU::NVIDIA::Setup::Apt>): the apt timers stopped
before the first C<apt-get>, a dpkg lock timeout on every C<apt-get>, the
install run directly and C<dpkg -l> (C<ii>, or C<hi> when held) as the
only evidence. And
L</install_rocm>, which is apt-only.

=head1 SEE ALSO

L<Rex::GPU::AMD::Setup>, L<Rex::GPU::AMD>

=cut

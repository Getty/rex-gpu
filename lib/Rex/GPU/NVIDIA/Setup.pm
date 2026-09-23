# ABSTRACT: Base class of the per-distro NVIDIA driver setups (experimental)

package Rex::GPU::NVIDIA::Setup;
our $VERSION = '0.002';
use Moo;
use Carp qw( croak );
use Rex::Commands::File ();
use Rex::Commands::Gather ();
use Rex::Commands::Pkg ();
use Rex::Commands::Run ();
use Rex::Logger ();
use Rex::GPU::NVIDIA::Requirement ();
use namespace::autoclean;

# No `use utf8` here, on purpose: the die messages carry UTF-8 em dashes as
# byte strings exactly like Rex::GPU::NVIDIA always emitted them.

=attr gpus

Arrayref of the detected GPUs this driver install is for, each in the shape
L<Rex::GPU::Detect/detect> returns for one C<nvidia> element (C<name>,
C<device_id>, ...). One driver has to drive them all, so L</requirement> is
the intersection of their requirements. Empty (the default) keeps the
GPU-agnostic package selection. Elements that are not hashrefs are ignored.

=attr gpu

A single GPU hashref, the older form of L</gpus>: C<< gpu => $g >> is the
same as C<< gpus => [ $g ] >>, C<< gpu => undef >> the same as no GPU.
Passing both croaks.

=cut

has gpu  => ( is => 'ro' );
has gpus => ( is => 'lazy' );

sub _build_gpus {
  my ( $self ) = @_;
  return defined $self->gpu ? [ $self->gpu ] : [];
}

sub BUILD {
  my ( $self, $args ) = @_;
  croak __PACKAGE__.'->new: pass gpu or gpus, not both'
    if defined $args->{gpu} && defined $args->{gpus};
  croak __PACKAGE__.'->new: gpus must be an arrayref of GPU hashrefs'
    if defined $args->{gpus} && ref $args->{gpus} ne 'ARRAY';
}

=attr requirement

The L<Rex::GPU::NVIDIA::Requirement> the driver has to meet: the
L<Rex::GPU::NVIDIA::Requirement/intersect> of every GPU in L</gpus>, looked
up through L</requirement_class>; C<either> with no bounds for no GPU. Built
on first use -- by L</plan> -- and B<dies> there, before anything on the
host is changed, when the GPUs need different kernel modules or no common
branch (a V100 next to a B200), naming the GPUs on each side. May be passed
to C<new> instead.

=method requirement_class

The requirement class, C<Rex::GPU::NVIDIA::Requirement>. Override it to use
a subclass with rows of your own in its
L<generations|Rex::GPU::NVIDIA::Requirement/generations> table.

=cut

has requirement => ( is => 'lazy' );

sub requirement_class { 'Rex::GPU::NVIDIA::Requirement' }

sub _build_requirement {
  my ( $self ) = @_;
  my $class = $self->requirement_class;
  my @gpus  = grep { ref $_ eq 'HASH' } @{ $self->gpus };
  return $class->new unless @gpus;
  my @reqs = map { $class->from_gpu($_) } @gpus;
  if ( my @conflicts = $class->conflicts(@reqs) ) {
    die 'No single NVIDIA driver supports all GPUs on this host: '
      .join('; ', @conflicts).'. Nothing was changed on the host. Install the '
      ."driver yourself; once `nvidia-smi -L` lists the GPUs, install_driver skips "
      ."the driver step\n";
  }
  return $class->intersect(@reqs);
}

=attr os

The OS name as L<Rex::Commands::Gather/operating_system> reports it
(C<Debian>, C<Ubuntu>, ...). Read from the host on first use unless passed
to C<new>.

=attr release

The raw release string, L<Rex::Commands::Gather/operating_system_release>
(C<12.11>, C<13.1>, C<10.0>, C<trixie/sid>). Never
C<operating_system_version>, which strips the dots (C<10.1> becomes C<101>).
Read on first use unless passed to C<new>.

=attr arch

The host architecture as the packaging layer names it. The base class reads
C<uname -m> (C<x86_64>, C<aarch64>); L<Rex::GPU::NVIDIA::Setup::Apt> reads
C<dpkg --print-architecture> (C<amd64>, C<arm64>). Read on first use unless
passed to C<new>.

=attr kernel

The running kernel, C<uname -r>. Read on first use unless passed to C<new>.

=cut

has os      => ( is => 'lazy' );
has release => ( is => 'lazy' );
has arch    => ( is => 'lazy' );
has kernel  => ( is => 'lazy' );

sub _build_os      { Rex::Commands::Gather::operating_system() }
sub _build_release { Rex::Commands::Gather::operating_system_release() }

sub _build_arch {
  my ( $self ) = @_;
  my $arch = $self->run_cmd('uname -m', auto_die => 0);
  chomp $arch if defined $arch;
  return $arch;
}

sub _build_kernel {
  my ( $self ) = @_;
  # auto_die left to Rex's default, as install_driver always read it
  my $kernel = $self->run_cmd('uname -r');
  chomp $kernel;
  return $kernel;
}

#### The host seam ############################################################

=method run_cmd

  my $out = $self->run_cmd('uname -r');
  $self->run_cmd('modprobe nvidia', auto_die => 0);

The only way this class and its subclasses run a command on the host: the
arguments go to L<Rex::Commands::Run/run> unchanged, in the caller's
context, and C<$?> is left as C<run> set it. Override it to record or fake
the host in a test.

=method pkg_cmd

The only way to L<Rex::Commands::Pkg/pkg>. Reserved for inert helpers
(C<curl>, C<gnupg>, C<epel-release>): C<Rex::Pkg> dies on the non-zero exit
that DKMS builds, grub and initramfs regeneration return on success, so a
driver or toolkit package never goes through it.

=method file_cmd

The only way to L<Rex::Commands::File/file>.

=cut

sub run_cmd  { my ( $self, @args ) = @_; return Rex::Commands::Run::run(@args) }
sub pkg_cmd  { my ( $self, @args ) = @_; return Rex::Commands::Pkg::pkg(@args) }
sub file_cmd { my ( $self, @args ) = @_; return Rex::Commands::File::file(@args) }

#### The flow #################################################################

=method install

  my $installed = $setup->install;

Runs the fixed sequence, each step a method a subclass can override:

  already_installed  -> return 0, nothing else runs
  plan               -> host-read-only; dies before any change
  prepare_host($plan)
  prepare_source($plan)
  install_packages($plan)
  verify_packages($plan)
  post_install($plan)

Returns C<1> after an install, C<0> if a working driver was already there.
Loading the module, rebooting and L<Rex::GPU::NVIDIA/verify_nvidia> are
still done by L<Rex::GPU::NVIDIA/install_driver> after this returns.

=cut

sub install {
  my ( $self ) = @_;
  return 0 if $self->already_installed;
  my $plan = $self->plan;
  $self->prepare_host($plan);
  $self->prepare_source($plan);
  $self->install_packages($plan);
  $self->verify_packages($plan);
  $self->post_install($plan);
  return 1;
}

=method already_installed

True if a working NVIDIA driver is loaded: C<nvidia-smi -L> lists a
C<GPU N:> device. Then nothing is installed, nouveau is not blacklisted and
the host is not rebooted, so a re-run, or a host provisioned from NVIDIA's
own repository, does not get a second, conflicting driver.

=cut

sub already_installed {
  my ( $self ) = @_;
  # nvidia-smi -L lists a "GPU N:" device only when the module is loaded and
  # functional, so it is the safe, OS-neutral signal. Distro-neutral and
  # BEFORE package selection: a host set up from NVIDIA's CUDA repo would
  # otherwise get a different (possibly lower) driver whose libs conflict.
  my $smi = $self->run_cmd('nvidia-smi -L 2>&1', auto_die => 0);
  chomp $smi if defined $smi;
  return 0 unless $self->_driver_present($smi);
  Rex::Logger::info("NVIDIA driver already present and working — skipping driver install ($smi)");
  return 1;
}

=method plan

  my $plan = $self->plan;

Decides what to install and returns it as a hashref: C<source> (the chosen
driver source, see L</sources>), C<packages> (arrayref, in install order:
L</kernel_packages>, then the source's) and C<verify> (the source's
packages that must be installed afterwards); a subclass adds keys for its
own later steps. Must only B<read> the host: every "this cannot work here"
dies from here, before anything is changed:

=over

=item * a GPU no installable driver branch supports (Kepler or older, even
one among several GPUs);

=item * GPUs that cannot share one driver (L</requirement>);

=item * no source that fits the requirement (L</select_source>).

=back

A class without L</sources> (the base class) gets an empty plan.

=method kernel_packages

The packages the driver build needs before any source's: kernel headers.
None in the base class.

=method sources

  my @candidates = $self->sources;

The driver sources this setup can install from, B<in order of preference>.
Each is a hashref:

=over

=item * C<name> -- for log lines and messages.

=item * C<kernel_module> -- C<open> or C<proprietary>.

=item * C<branch> -- the exact driver branch it installs; or
C<branch_at_least> when it installs the newest branch its repository
carries, which is known only to be at least that one (see
L<Rex::GPU::NVIDIA::Requirement/satisfied_by> for how each counts); or
neither when the branch is unknown.

=item * C<packages>, C<verify> -- as in L</plan>. May be filled only by
L</resolve_source>.

=item * C<unavailable> -- a reason: this source does not exist on this host
(no repository for the release or architecture). Skipped with that reason.

=back

Plus whatever keys the class's later steps read. Host-read-only, like
L</plan>. Empty in the base class. Override it in a subclass to add,
reorder or drop candidates; C<< $self->SUPER::sources >> gives the built-in
ones.

=method select_source

  my $source = $self->select_source(@candidates);

The first candidate L</requirement> accepts
(L<Rex::GPU::NVIDIA::Requirement/satisfied_by>), after
L</resolve_source> -- which is checked again, so a resolved branch that does
not fit moves on to the next candidate. Dies when none fits, naming the
GPUs, what they need and every rejected candidate with its reason; nothing
has been changed on the host then.

=method resolve_source

  my $resolved = $self->resolve_source($source);

Turns a chosen candidate into a concrete one: the base class returns it
unchanged; L<Rex::GPU::NVIDIA::Setup::Ubuntu> asks C<apt-cache search> for
the newest package and records its branch. Only for a candidate that
already fits; must only read the host.

=cut

sub plan {
  my ( $self ) = @_;
  # Kepler or older (karr #26), on any GPU in the list: die here, after
  # already_installed (a host whose operator installed 470 by hand still
  # passes) and before anything on the host is changed or even read.
  $self->_reject_unsupported_gpu($_) for @{ $self->gpus };
  # Multi-GPU (karr #33): one driver for all of them, or die untouched.
  my $requirement = $self->requirement;
  Rex::Logger::info('Installing NVIDIA drivers on '.$self->os.' (kernel '.$self->kernel.')');
  Rex::Logger::info('  Driver requirement: '.$requirement->who.': '.$requirement->describe)
    if @{ $self->gpus };

  my $plan = { packages => [ $self->kernel_packages ], verify => [] };
  my @sources = $self->sources;
  return $plan unless @sources;
  my $source = $self->select_source(@sources);
  $plan->{source} = $source;
  push @{ $plan->{packages} }, @{ $source->{packages} // [] };
  $plan->{verify} = [ @{ $source->{verify} // [] } ];
  return $plan;
}

sub kernel_packages { () }
sub sources         { () }

sub resolve_source {
  my ( $self, $source ) = @_;
  return $source;
}

sub select_source {
  my ( $self, @candidates ) = @_;
  my $requirement = $self->requirement;
  my @rejected;
  for my $candidate (@candidates) {
    my $why = $candidate->{unavailable} // $requirement->why_not($candidate);
    unless (defined $why) {
      my $resolved = $self->resolve_source($candidate);
      $why = $requirement->why_not($resolved);
      unless (defined $why) {
        Rex::Logger::info('  Driver source: '.$resolved->{name});
        return $resolved;
      }
    }
    push @rejected, $candidate->{name}.': '.$why;
  }
  die 'No NVIDIA driver source on this '.$self->os.' '.( $self->release // '' ).' host fits '
    .$requirement->who.' ('.$requirement->describe.') -- '.join('; ', @rejected)
    .'. Nothing was changed on the host. Install the driver yourself; once '
    ."`nvidia-smi -L` lists the GPU, install_driver skips the driver step\n";
}

=method prepare_host

Readies the host's own package manager.

=method prepare_source

Registers and refreshes the repository the driver comes from.

=method install_packages

Installs C<< $plan->{packages} >>.

=method verify_packages

Dies unless every package in C<< $plan->{verify} >> ended up installed. That
check, not the package manager's exit code, is the evidence of an install.

Each of these four takes the C<$plan> from L</plan> and does nothing in the
base class; the packaging layer (L<Rex::GPU::NVIDIA::Setup::Apt>,
L<Rex::GPU::NVIDIA::Setup::Rpm>) and the distro classes fill them.

=cut

sub prepare_host     { }
sub prepare_source   { }
sub install_packages { }
sub verify_packages  { }

=method post_install

Blacklists C<nouveau> in C</etc/modprobe.d/blacklist-nouveau.conf> and runs
L</initramfs_command>, so the blacklist takes effect on the next boot.

=method initramfs_command

The command that regenerates the initramfs: C<dracut --force 2E<gt>/dev/null>
here (and so on the rpm layer), C<update-initramfs -u 2E<gt>/dev/null> in
L<Rex::GPU::NVIDIA::Setup::Apt>. Run with C<auto_die =E<gt> 0>.

=cut

sub post_install {
  my ( $self ) = @_;
  $self->file_cmd('/etc/modprobe.d/blacklist-nouveau.conf',
    content => "blacklist nouveau\noptions nouveau modeset=0\n");
  $self->run_cmd($self->initramfs_command, auto_die => 0);
}

sub initramfs_command { 'dracut --force 2>/dev/null' }

#### Pure helpers #############################################################
#
# Callable on the class as on an object, and with explicit arguments, because
# Rex::GPU::NVIDIA keeps some old private names as thin wrappers over them
# (t/ calls those).

# Given `nvidia-smi -L` output: is a working driver loaded? Every failure form
# (NVML init error, "No devices were found", "command not found") does not
# match.
sub _driver_present {
  my ( $self, $smi ) = @_;
  return 0 unless defined $smi;
  return $smi =~ /GPU \d+:/ ? 1 : 0;
}

# Die for a GPU no installable branch supports -- Kepler or older, max_branch
# 470. Maintainer decision (epic karr #25): reject loudly instead of
# installing the EOL 470 driver. Quiet for every other GPU, 580 included, and
# for anything that is not a GPU hashref.
sub _reject_unsupported_gpu {
  my ( $self, $gpu ) = @_;
  return unless $gpu && ref $gpu eq 'HASH';
  my $req = $self->requirement_class->from_gpu($gpu);
  return unless defined $req->max_branch && $req->max_branch < 580;
  die "NVIDIA GPU '" . ($gpu->{name} // 'unknown') . "' (10de:$gpu->{device_id}) is "
    . $req->generation." silicon: no driver newer than the end-of-life "
    . $req->max_branch." branch supports it, and Rex::GPU does not install "
    . "that. Nothing was changed on the host. Install the driver yourself; once "
    . "`nvidia-smi -L` lists the GPU, install_driver skips the driver step\n";
}

# `uname -m` / dpkg arch -> the token NVIDIA's CUDA repos use under
# repos/<distro>/<arch>/: aarch64/arm64 are "sbsa", everything else (an empty
# string included) "x86_64". NOT the libnvidia-container toolkit repo's token,
# which is "aarch64" for the same machine.
sub _cuda_repo_arch {
  my ( $self, $machine ) = @_;
  $machine //= '';
  return 'sbsa' if $machine eq 'aarch64' || $machine eq 'arm64';
  return 'x86_64';
}

# Major version from a raw release string ("10.1" -> 10, "trixie/sid" -> 0).
# operating_system_version() strips the dots, so it is never the input.
sub _major_version {
  my ( $self, $release ) = @_;
  my ($major) = ($release // '') =~ /^(\d+)/;
  return ($major // 0) + 0;
}

1;

=head1 SYNOPSIS

  package My::GPU::Setup;
  use Moo;
  extends 'Rex::GPU::NVIDIA::Setup::Ubuntu';

  # one more step before the packages go in
  sub prepare_source {
    my ( $self, $plan ) = @_;
    $self->run_cmd('add-apt-repository -y ppa:my/mirror', auto_die => 0);
    $self->SUPER::prepare_source($plan);
  }

=head1 DESCRIPTION

B<Experimental.> The class layout, the step names, the source keys and the
C<$plan> keys may change in the next release without a deprecation cycle;
there is no option yet that makes L<Rex::GPU::NVIDIA/install_driver> use a
class of your own.

One driver install is one object: the GPUs and the host facts it was built
with, and a fixed L</install> sequence of overridable steps. Which driver it
installs is not a per-distro special case but data: the GPUs'
L</requirement> against the ordered L</sources>, the first that fits wins
(L</select_source>). The per-distro
classes are L<Rex::GPU::NVIDIA::Setup::Debian> and
L<Rex::GPU::NVIDIA::Setup::Ubuntu> on the apt packaging layer
L<Rex::GPU::NVIDIA::Setup::Apt>, and L<Rex::GPU::NVIDIA::Setup::RHEL> and
L<Rex::GPU::NVIDIA::Setup::SUSE> on the rpm packaging layer
L<Rex::GPU::NVIDIA::Setup::Rpm>.

Every host interaction goes through L</run_cmd>, L</pkg_cmd> and
L</file_cmd>.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA>, L<Rex::GPU::NVIDIA::Requirement>

=cut

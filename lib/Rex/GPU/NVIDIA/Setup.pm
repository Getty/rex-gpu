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
use Scalar::Util qw( blessed );
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
has gpus => ( is => 'lazy', writer => '_set_gpus' );

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

# extra_requirement may be given as a plain hashref; it becomes an object of
# the class's requirement_class here, so a typo croaks at construction -- on
# every host, not only on one that gets as far as plan.
around BUILDARGS => sub {
  my ( $orig, $class, @args ) = @_;
  my $args = $class->$orig(@args);
  $args->{extra_requirement} = $class->_coerce_requirement($args->{extra_requirement})
    if defined $args->{extra_requirement};
  return $args;
};

=attr requirement

The L<Rex::GPU::NVIDIA::Requirement> the driver has to meet: the
L<Rex::GPU::NVIDIA::Requirement/intersect> of every GPU in L</gpus>, looked
up through L</requirement_class>; C<either> with no bounds for no GPU. Built
on first use -- by L</plan> -- and B<dies> there, before anything on the
host is changed, when the GPUs need different kernel modules or no common
branch (a V100 next to a B200), naming the GPUs on each side. May be passed
to C<new> instead.

=attr extra_requirement

  My::GPU::Setup->new(extra_requirement => { kernel_module => 'open', min_branch => 580 });

An additional constraint of your own, B<intersected> with what the GPUs
need -- the C<requirement> option of L<Rex::GPU::NVIDIA/install_driver> and
L<Rex::GPU/gpu_setup> ends up here. It can only tighten: a V100 stays
C<proprietary> and at most 580 whatever you ask for, and a constraint the
GPUs cannot meet (C<open> on a V100) makes L</plan> die before anything on
the host is changed, naming both sides. With no GPU it is the whole
requirement.

A hashref with the keys C<kernel_module>, C<min_branch>, C<max_branch> and
optionally C<name> (for messages; default C<the requirement option>), or a
L<Rex::GPU::NVIDIA::Requirement> object. A hashref becomes an object of
L</requirement_class> in C<new>, so an unknown key or a bad value croaks
there. C<undef> (the default) adds nothing.

=method requirement_class

The requirement class, C<Rex::GPU::NVIDIA::Requirement>. Override it to use
a subclass with rows of your own in its
L<generations|Rex::GPU::NVIDIA::Requirement/generations> table.

=cut

has requirement => ( is => 'lazy', predicate => '_has_requirement' );

has extra_requirement => ( is => 'ro', writer => '_set_extra_requirement' );

sub requirement_class { 'Rex::GPU::NVIDIA::Requirement' }

sub _build_requirement {
  my ( $self ) = @_;
  my $class = $self->requirement_class;
  my $extra = $self->extra_requirement;
  my @gpus  = grep { ref $_ eq 'HASH' } @{ $self->gpus };
  return $extra // $class->new unless @gpus;
  my @reqs = map { $class->from_gpu($_) } @gpus;
  if ( my @conflicts = $class->conflicts(@reqs) ) {
    die 'No single NVIDIA driver supports all GPUs on this host: '
      .join('; ', @conflicts).'. Nothing was changed on the host. Install the '
      ."driver yourself; once `nvidia-smi -L` lists the GPUs, install_driver skips "
      ."the driver step\n";
  }
  my $gpu_req = $class->intersect(@reqs);
  return $gpu_req unless $extra;
  # The user's requirement only tightens (karr #34): a conflict with what the
  # GPUs need dies here, in plan, before anything on the host is changed.
  if ( my @conflicts = $class->conflicts($gpu_req, $extra) ) {
    die 'No NVIDIA driver meets both what the GPUs need and '.$extra->who.' ('
      .$extra->describe.'): '.join('; ', @conflicts).'. Nothing was changed on the '
      ."host. Loosen the requirement, or install the driver yourself\n";
  }
  return $class->intersect($gpu_req, $extra);
}

my %REQUIREMENT_KEY = map { $_ => 1 } qw( kernel_module min_branch max_branch name );

# A hashref or requirement object -> requirement object. Callable on the class
# (BUILDARGS) and on an object (adopt).
sub _coerce_requirement {
  my ( $self, $req ) = @_;
  my $base = 'Rex::GPU::NVIDIA::Requirement';
  return $req if blessed($req) && $req->isa($base);
  croak __PACKAGE__.': a requirement is a hashref or a '.$base.' object, not '
    .( defined $req ? "'".$req."'" : 'undef' )
    unless ref $req eq 'HASH';
  my @unknown = sort grep { !$REQUIREMENT_KEY{$_} } keys %$req;
  croak __PACKAGE__.': unknown requirement key'.( @unknown == 1 ? '' : 's' ).' '
    .join(', ', @unknown).' -- known: kernel_module, min_branch, max_branch, name'
    if @unknown;
  return $self->requirement_class->new(name => 'the requirement option', %$req);
}

=method adopt

  $setup->adopt(gpus => \@gpus, extra_requirement => { min_branch => 580 });

What L<Rex::GPU::NVIDIA/install_driver> does to a setup B<object> passed as
C<setup>: it hands over the GPUs it was called with and its C<requirement>
option. C<gpus> is taken only if the object has none of its own (built
without C<gpu>/C<gpus>, or with an empty list) -- an object built for
specific GPUs keeps them. C<extra_requirement> (hashref or object, see
L</extra_requirement>) is set if given. Returns the object.

Croaks, before anything on the host is changed, if the object has already
run L</install> -- it caches the host facts (L</os>, L</kernel>, ...) of
that host, so one object serves one host -- or if it would have to change
an object whose L</requirement> is already fixed (passed to C<new>, or built
by an earlier L</plan>) -- the detected GPUs would otherwise not be checked
-- or if both the object and the option carry an C<extra_requirement>.

=cut

sub adopt {
  my ( $self, %arg ) = @_;
  my $gpus  = $arg{gpus} // [];
  croak __PACKAGE__.'->adopt: gpus must be an arrayref of GPU hashrefs'
    unless ref $gpus eq 'ARRAY';
  croak ref($self).' object passed as setup => has already run install -- it '
    .'holds that host\'s facts and GPUs. Build a new object per host, or pass a '
    .'class name. Nothing was changed on the host'
    if $self->_installed;
  my $extra = defined $arg{extra_requirement}
    ? $self->_coerce_requirement($arg{extra_requirement}) : undef;
  my $take_gpus = @$gpus && !@{ $self->gpus };
  return $self unless $take_gpus || $extra;
  croak ref($self).' object passed as setup => already has a fixed requirement '
    .'(given to new or built by plan), so the detected GPUs or the requirement '
    .'option could not be checked. Build it without requirement =>, or pass a '
    .'class name. Nothing was changed on the host'
    if $self->_has_requirement;
  croak ref($self).' object passed as setup => has an extra_requirement of its '
    .'own and the requirement option was given too; pass one of them. Nothing '
    .'was changed on the host'
    if $extra && $self->extra_requirement;
  $self->_set_gpus($gpus) if $take_gpus;
  $self->_set_extra_requirement($extra) if $extra;
  return $self;
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
  resolve_plan($plan) -> fixes the packages; dies before any install
  install_packages($plan)
  verify_packages($plan)
  post_install($plan)

Returns C<1> after an install, C<0> if a working driver was already there.
Loading the module (C<modprobe nvidia>) or rebooting, and
L<Rex::GPU::NVIDIA/verify_nvidia>, are done by
L<Rex::GPU::NVIDIA/install_driver> after this returns, not by the setup:
the reboot is a per-call option that needs Rex's live connection, and
C<verify_nvidia> is an exported check that also looks for the container
toolkit.

=cut

# Set once install starts: the object has read (and cached) one host's facts
# and GPUs, so adopt refuses to hand it to another host.
has _installed => ( is => 'rwp', init_arg => undef );

sub install {
  my ( $self ) = @_;
  $self->_set__installed(1);
  return 0 if $self->already_installed;
  my $plan = $self->plan;
  $self->prepare_host($plan);
  $self->prepare_source($plan);
  $self->resolve_plan($plan);
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
own later steps. A source whose packages are known only once its
repository is refreshed (see L</resolve_source>) has none here yet;
L</resolve_plan> adds them. Must only B<read> the host: every "this cannot
work here" that is known without a refreshed package index dies from here,
before anything is changed:

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
L</resolve_source>, after the repository is refreshed.

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
(L<Rex::GPU::NVIDIA::Requirement/satisfied_by>) on what it declares --
C<kernel_module>, C<branch> or C<branch_at_least>, C<unavailable>. Called
by L</plan>, so it must only read the host, and it does not look at a
package index: on a fresh host that index is stale or empty until
L</prepare_source> refreshes it. Dies when none fits, naming the GPUs, what
they need and every rejected candidate with its reason; nothing has been
changed on the host then.

=method resolve_plan

  $self->resolve_plan($plan);

The step between L</prepare_source> and L</install_packages>: passes the
chosen source through L</resolve_source>, now that its repository is
refreshed, and checks the result against L</requirement> again. If
L</resolve_source> returned a new source, it goes into C<$plan>: C<source>,
C<packages> (the plan's other packages, then the resolved source's) and
C<verify>. Dies, before any driver package is installed, when the resolved
source is C<unavailable> or no longer fits; the source L</plan> chose is not
swapped for another candidate then. A plan without a source is left alone.

=method resolve_source

  my $resolved = $self->resolve_source($source);

Turns the chosen source into a concrete one, called by L</resolve_plan>
after L</prepare_source> has refreshed the package index. The base class
returns it unchanged (the same reference: nothing to do);
L<Rex::GPU::NVIDIA::Setup::Ubuntu> asks C<apt-cache search> for the newest
package and records its branch. Returns a new hashref with C<packages>,
C<verify> and, if known, the exact C<branch> -- or with C<unavailable> set
to the reason when the repository has nothing to install. May read the
host, must not change it. Override it to pick the package some other way (a
site index, C<ubuntu-drivers list>); L</resolve_plan> checks whatever it
returns against the requirement.

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
    if @{ $self->gpus } || $self->extra_requirement;

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
      Rex::Logger::info('  Driver source: '.$candidate->{name});
      return $candidate;
    }
    push @rejected, $candidate->{name}.': '.$why;
  }
  die 'No NVIDIA driver source on this '.$self->os.' '.( $self->release // '' ).' host fits '
    .$requirement->who.' ('.$requirement->describe.') -- '.join('; ', @rejected)
    .'. Nothing was changed on the host. Install the driver yourself; once '
    ."`nvidia-smi -L` lists the GPU, install_driver skips the driver step\n";
}

sub resolve_plan {
  my ( $self, $plan ) = @_;
  my $source = $plan->{source} or return;
  # After prepare_source (karr #35): the package index is fresh now, so a
  # source that picks its package from it (Ubuntu's apt-cache search) sees
  # what the repository carries, not a fresh image's stale or empty lists.
  my $resolved = $self->resolve_source($source);
  my $requirement = $self->requirement;
  my $why = $resolved->{unavailable} // $requirement->why_not($resolved);
  die 'The NVIDIA driver source '.$source->{name}.' chosen for '.$requirement->who
    .' ('.$requirement->describe.') has nothing to install on this '.$self->os.' '
    .( $self->release // '' ).' host: '.$why.'. No driver package was installed, '
    .'only the package sources were prepared. Install the driver yourself; once '
    ."`nvidia-smi -L` lists the GPU, install_driver skips the driver step\n"
    if defined $why;
  return if $resolved == $source;
  my %old = map { $_ => 1 } @{ $source->{packages} // [] };
  $plan->{source}   = $resolved;
  $plan->{packages} = [ ( grep { !$old{$_} } @{ $plan->{packages} } ),
    @{ $resolved->{packages} // [] } ];
  $plan->{verify}   = [ @{ $resolved->{verify} // [] } ];
  Rex::Logger::info('  Driver packages: '.join(', ', @{ $resolved->{packages} // [] }));
  return;
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

Each of these four takes the C<$plan> from L</plan> (completed by
L</resolve_plan> before L</install_packages>) and does nothing in the base
class; the packaging layer (L<Rex::GPU::NVIDIA::Setup::Apt>,
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
C<$plan> keys may change in the next release without a deprecation cycle.
L<Rex::GPU::NVIDIA/install_driver> and L<Rex::GPU/gpu_setup> use a class of
your own when told to -- see L</WRITING YOUR OWN SETUP>.

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

=head1 WRITING YOUR OWN SETUP

A setup of your own is a Moo class that extends one of the built-in ones and
overrides what it needs to; nothing in Rex::GPU has to be patched. Put it in
your Rex project's C<lib/> directory -- Rex puts the C<lib/> next to the
Rexfile, and the one in the current directory, first on C<@INC> -- or write
the package straight into the Rexfile:

  my-project/
    Rexfile
    lib/My/GPU/Setup.pm

=head2 Adding a driver source

Override L</sources> and put your candidate first; C<SUPER::sources> keeps
the built-in ones behind it. The GPUs' L</requirement> still decides: a
source they cannot use is skipped with its reason, and the next one is
tried.

  package My::GPU::Setup;
  use Moo;
  use namespace::autoclean;
  extends 'Rex::GPU::NVIDIA::Setup::Ubuntu';

  sub sources {
    my ( $self ) = @_;
    return (
      {
        name            => 'pinned-580-open',
        kernel_module   => 'open',
        branch          => 580,
        packages        => [ 'nvidia-driver-580-server-open' ],
        verify          => [ 'nvidia-driver-580-server-open' ],
        check_candidate => 'nvidia-driver-580-server-open'
      },
      $self->SUPER::sources
    );
  }

  1;

An Ada or a B200 gets the pinned open driver; a V100 (proprietary only)
rejects it and gets the built-in C<nvidia-driver-580-server>.
C<check_candidate> is a key L<Rex::GPU::NVIDIA::Setup::Ubuntu> reads in its
C<resolve_source>, after C<apt-get update>; which extra keys a source may carry depends on the class
you extend.

=head2 Changing a step

Override the step and call C<SUPER::> for the built-in part. Reach the host
only through L</run_cmd> and L</file_cmd> (L</pkg_cmd> only for inert
helpers such as C<curl>): the driver packages are installed and verified by
the packaging layer's L</install_packages> and L</verify_packages>, never
through C<Rex::Pkg>, which dies on the non-zero exit a successful DKMS build
can return. L</plan> and everything it calls must only read the host.

  has apt_line => ( is => 'ro', predicate => 1 );

  # a local mirror, in before the inherited step runs `apt-get update`
  sub prepare_source {
    my ( $self, $plan ) = @_;
    $self->file_cmd('/etc/apt/sources.list.d/internal-nvidia.list',
      content => $self->apt_line."\n") if $self->has_apt_line;
    $self->SUPER::prepare_source($plan);
  }

=head2 Choosing it

First hit wins (L<Rex::GPU::NVIDIA/setup_for>):

  # 1. per call -- a class name, or an object with settings of its own
  gpu_setup(setup => 'My::GPU::Setup');
  gpu_setup(setup => My::GPU::Setup->new(apt_line => 'deb [...] http://... noble main'));

  # 2. for the whole Rexfile -- also reaches Rex::Rancher's gpu => 1
  set gpu_nvidia_setup => 'My::GPU::Setup';

  # 3. neither: Rex::GPU::NVIDIA->setup_class_for_os

The same C<setup> option works on L<Rex::GPU::NVIDIA/install_driver>. The
class is built with the detected GPUs (C<gpus>); an object gets them through
L</adopt> if it has none. A class extends one distro's setup, so it is for
hosts of that distro: to cover several, choose per host in the Rexfile, or
override L<Rex::GPU::NVIDIA/setup_class_for_os> in a subclass of
L<Rex::GPU::NVIDIA>.

To narrow the driver choice without a class, pass C<requirement> (see
L</extra_requirement>). To teach the GPU table a device, override
L</requirement_class> with a L<Rex::GPU::NVIDIA::Requirement> subclass that
adds rows to its C<generations>.

A runnable example: C<eg/custom-setup/> in the distribution.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA>, L<Rex::GPU::NVIDIA::Requirement>

=cut

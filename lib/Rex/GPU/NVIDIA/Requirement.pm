# ABSTRACT: What NVIDIA driver a GPU generation needs (experimental)

package Rex::GPU::NVIDIA::Requirement;
our $VERSION = '0.002';
use Moo;
use Carp qw( croak );
use Scalar::Util qw( blessed );
use namespace::autoclean;

my %KERNEL_MODULES = map { $_ => 1 } qw( open proprietary either );

=attr generation

A label for the GPU generation (C<Blackwell>, C<Maxwell/Pascal/Volta>, ...)
taken from L</generations>, for messages. C<undef> for a device ID the table
does not know, and for a requirement built by L</intersect> from several
GPUs.

=cut

has generation => ( is => 'ro' );

=attr kernel_module

Which NVIDIA kernel module the GPU binds with: C<open> (NVIDIA's open GPU
kernel modules only — Blackwell has no proprietary module),
C<proprietary> (the closed module only — pre-Turing silicon lacks the GSP the
open module needs) or C<either>. Defaults to C<either>.

=cut

has kernel_module => (
  is      => 'ro',
  default => 'either',
  isa     => sub {
    croak __PACKAGE__.'->kernel_module must be open, proprietary or either, not '
      .( defined $_[0] ? "'".$_[0]."'" : 'undef' )
      unless defined $_[0] && $KERNEL_MODULES{ $_[0] };
  }
);

=attr min_branch

The oldest driver branch (an integer, e.g. C<570>) that supports the GPU, or
C<undef> for no lower bound.

=attr max_branch

The newest driver branch that still supports the GPU (e.g. C<580> for
Maxwell/Pascal/Volta, whose support ends there), or C<undef> for no upper
bound.

=cut

has min_branch => ( is => 'ro', isa => \&_check_branch );
has max_branch => ( is => 'ro', isa => \&_check_branch );

sub _check_branch {
  my ( $branch ) = @_;
  croak __PACKAGE__.': a driver branch is an integer like 580, not '."'".$branch."'"
    if defined $branch && $branch !~ /^\d+\z/;
}

=attr device_id

The lowercase PCI device ID (the C<XXXX> in C<[10de:XXXX]>) the requirement
was looked up for, or C<undef> (no or malformed ID, or an intersected
requirement).

=cut

has device_id => (
  is  => 'ro',
  isa => sub {
    croak __PACKAGE__.'->device_id must be four lowercase hex digits, not '."'".$_[0]."'"
      if defined $_[0] && $_[0] !~ /^[0-9a-f]{4}\z/;
  }
);

=attr name

The GPU name from detection (L</from_gpu>), for messages only. Never used to
decide anything.

=attr members

For a requirement built by L</intersect> from several GPUs: an arrayref of
the per-GPU requirements it combines, so a message can name every GPU that
constrained it. Empty for a per-GPU requirement.

=cut

has name    => ( is => 'ro' );
has members => ( is => 'ro', default => sub { [] } );

sub BUILD {
  my ( $self ) = @_;
  croak __PACKAGE__.': min_branch '.$self->min_branch.' is above max_branch '
    .$self->max_branch.': no driver branch can satisfy that'
    if defined $self->min_branch && defined $self->max_branch
      && $self->min_branch > $self->max_branch;
}

=method generations

  my @rows = $class->generations;

The generation table: an ordered list of hashrefs, each covering the
inclusive PCI device-ID range C<first>..C<last> (numbers) with a
C<generation> label, a C<kernel_module> (default C<either>) and optional
C<min_branch>/C<max_branch>. The B<first> row whose range contains an ID
wins, so a narrower row goes before a block it sits in. An ID no row covers
gets C<either> with no bounds — which is also what the driver installer does
for every Turing-to-Hopper part today, so those generations have no rows.

Override it in a subclass to add or replace rows; prepend to
C<< $self->SUPER::generations >> to keep the built-in ones:

  package My::GPU::Requirement;
  use Moo;
  extends 'Rex::GPU::NVIDIA::Requirement';

  sub generations {
    my ( $self ) = @_;
    return (
      { generation => 'Hopper (site policy)', first => 0x2330, last => 0x2330,
        kernel_module => 'open', min_branch => 575 },
      $self->SUPER::generations
    );
  }

The table only chooses a driver. It never makes a GPU compute-capable: that
is decided by L<Rex::GPU::Detect> alone, and an unrecognised GPU still gets no
driver at all.

Sources, all checked 2026-09-23:

=over

=item * Blackwell C<2900>-C<2FFF> (B200 C<2901>, GB200 C<2941>, GeForce RTX 50xx,
RTX PRO Blackwell, GB10 C<2E12>) and Blackwell Ultra (B300 C<3182>, GB300
C<31C2>/C<31C3>, listed one by one, not as a block): the supported-GPU table
in NVIDIA's open-gpu-kernel-modules README (driver 615.71.09). The last Ada ID
there is C<28F8>, and every listed ID from C<2901> to C<2F58> is Blackwell,
so an unlisted ID in C<2900>-C<2FFF> is taken as Blackwell too. Open kernel
module only; oldest branch 570 (Blackwell) and 580 (Blackwell Ultra).

=item * GB10 C<2E12> (DGX Spark, aarch64) has its own row ahead of the
Blackwell block with the same values: it is the one Blackwell part verified
on real hardware (karr #15).

=item * Maxwell/Pascal/Volta C<1340>-C<1DF6> (Tesla M60/M40, P100, P40, P4, V100,
V100S, TITAN V, ...): the 580 legacy list of NVIDIA's C<supportedchips>
README (615.71.09). Proprietary kernel module only; 580 is the last branch.

=item * Kepler or older, every ID below C<1340> (Kepler C<0FC6>-C<12BA>, Fermi and
earlier): the 470 and older legacy lists. Proprietary only, nothing newer
than 470. L<Rex::GPU::NVIDIA> refuses to install for these.

=back

=cut

# The rows, and where they come from (moved here from Rex::GPU::Detect, karr
# #16 and #26). No row ever makes a device compute: a GPU still has to pass
# Rex::GPU::Detect::_is_nvidia_compute by class 0302, the device-ID allowlist
# or its name, and the unknown-model default there stays compute => 0.
#
# Blackwell (karr #16): NO proprietary kernel module — NVIDIA's open GPU
# kernel modules are the only ones that bind — on every architecture, x86_64
# included. Source: the supported-GPU table in NVIDIA's open-gpu-kernel-modules
# README.md (github.com/NVIDIA/open-gpu-kernel-modules, driver 615.71.09). In
# that table the last pre-Blackwell (Ada) ID is 28F8, and every listed ID from
# 2901 up to 2F58 is Blackwell: B200 (2901, 2909), GB200 (2941), GeForce RTX
# 50xx desktop/laptop and RTX PRO Blackwell (2B85..2F58), GB10 (2E12).
# 0x2900-0x2FFF is therefore taken as a block: an unlisted ID inside it is
# post-Ada silicon and gets the open module (which supports every GPU from
# Turing on). Blackwell Ultra (B300 3182, GB300 31C2/31C3) is listed
# explicitly, NOT as a block — whatever else lands at 0x3000+ is unknown.
# min_branch 570 / 580: the first branch with Blackwell / Blackwell Ultra
# support (research for epic karr #25). Not used by any install path yet.
#
# Pre-Turing (karr #26). Source: the legacy sections of NVIDIA's
# supportedchips README (driver 615.71.09, us.download.nvidia.com/XFree86/
# Linux-x86_64/615.71.09/README/supportedchips.html), checked 2026-09-23:
#   * "current" list: lowest ID 1E02 (TITAN RTX, Turing). No current ID < 1E02.
#   * 580.xx legacy list (Maxwell/Pascal/Volta): exactly 1340..1DF6, e.g.
#     Tesla M60 13F2, M40 17FD, P100 15F7/15F8, P40 1B38, P4 1BB3, TITAN V
#     1D81, V100 1DB1/1DB4-1DB6, V100S 1DF6. Proprietary kernel module only —
#     the open module needs GSP, which these chips lack — and 580 is their last
#     branch (595+ dropped them).
#   * 470.xx list (Kepler): 0FC6..12BA. The 390.xx (Fermi) list interleaves
#     with it (1040..1251) and goes down to 06C0; older legacy lists reach
#     down to 0020. No list has an ID in 12BB..133F or 1DF7..1E01.
# So every ID below 1340 is Kepler or older and no driver newer than 470
# supports it: one block, not a Kepler-only range, so a Fermi Tesla (C2050
# 06D1, M2090 1091) is rejected too. 1340..1DF6 is taken as a block like the
# Blackwell one: an unlisted ID inside it is Maxwell..Volta silicon.
#
# Everything else — 1DF7 up to 28FF (Turing, Ampere, Ada, Hopper), the gaps
# above 2FFF and any future ID — has no row: either kernel module, no bounds,
# which is the driver selection those GPUs get today.
sub generations {
  return (
    { generation => 'Blackwell', first => 0x2e12, last => 0x2e12,       # GB10, verified
      kernel_module => 'open', min_branch => 570 },
    { generation => 'Blackwell', first => 0x2900, last => 0x2fff,       # GB100/GB102, GB20x, GB10
      kernel_module => 'open', min_branch => 570 },
    { generation => 'Blackwell Ultra', first => 0x3182, last => 0x3182, # B300 SXM6 AC
      kernel_module => 'open', min_branch => 580 },
    { generation => 'Blackwell Ultra', first => 0x31c2, last => 0x31c3, # GB300
      kernel_module => 'open', min_branch => 580 },
    { generation => 'Maxwell/Pascal/Volta', first => 0x1340, last => 0x1df6,
      kernel_module => 'proprietary', max_branch => 580 },
    { generation => 'Kepler or older', first => 0x0000, last => 0x133f,
      kernel_module => 'proprietary', max_branch => 470 }
  );
}

=method for_device_id

  my $req = Rex::GPU::NVIDIA::Requirement->for_device_id('1db4');

The requirement for one NVIDIA PCI device ID (the C<XXXX> in C<[10de:XXXX]>,
any case), looked up in L</generations>. C<undef>, a malformed ID and an ID
no row covers all return a requirement of C<either> with no bounds. Called on
a subclass, it returns an object of that subclass and uses its table.

=method from_gpu

  my $req = Rex::GPU::NVIDIA::Requirement->from_gpu($gpu);

The same for a GPU hashref as returned by L<Rex::GPU::Detect/detect>: looks
up its C<device_id> and carries its C<name> along for messages. Croaks unless
C<$gpu> is a hashref.

=cut

sub for_device_id {
  my ( $self, $device_id ) = @_;
  return ( ref $self || $self )->new( $self->_lookup( $device_id ) );
}

sub from_gpu {
  my ( $self, $gpu ) = @_;
  croak __PACKAGE__.'->from_gpu needs a GPU hashref from Rex::GPU::Detect::detect'
    unless ref $gpu eq 'HASH';
  return ( ref $self || $self )->new(
    $self->_lookup( $gpu->{device_id} ),
    defined $gpu->{name} ? ( name => $gpu->{name} ) : ()
  );
}

# Constructor arguments for a device ID. The format check is the one
# Rex::GPU::Detect used before this table existed, kept as it was so the
# wrappers there return exactly what they did.
sub _lookup {
  my ( $self, $device_id ) = @_;
  return () unless defined $device_id && $device_id =~ /^[0-9a-f]{4}$/i;
  my $id = hex $device_id;
  my %args = ( device_id => lc substr( $device_id, 0, 4 ) );
  for my $row ( $self->generations ) {
    croak __PACKAGE__.'->generations: every row needs first and last'
      unless defined $row->{first} && defined $row->{last};
    next unless $id >= $row->{first} && $id <= $row->{last};
    return (
      %args,
      generation    => $row->{generation},
      kernel_module => $row->{kernel_module} // 'either',
      defined $row->{min_branch} ? ( min_branch => $row->{min_branch} ) : (),
      defined $row->{max_branch} ? ( max_branch => $row->{max_branch} ) : ()
    );
  }
  return %args;
}

=method satisfied_by

  $req->satisfied_by({ kernel_module => 'open', branch => 580 });   # 1 or 0

Whether a driver source — a concrete package set with a C<kernel_module>
(C<open> or C<proprietary>) and an integer C<branch> — satisfies this
requirement. A requirement of C<either> takes any kernel module; otherwise the
module must match exactly. The branch must lie within
L</min_branch>..L</max_branch>, both inclusive. A source whose C<branch> is
C<undef> (not known yet) satisfies only a requirement without bounds, and one
whose C<kernel_module> is missing only a requirement of C<either>: an unknown
never passes a real constraint. Croaks unless C<$source> is a hashref, or if
its C<branch> is not an integer.

=cut

sub satisfied_by {
  my ( $self, $source ) = @_;
  croak __PACKAGE__.'->satisfied_by needs a source hashref { kernel_module, branch }'
    unless ref $source eq 'HASH';
  my $branch = $source->{branch};
  croak __PACKAGE__.'->satisfied_by: branch must be an integer like 580, not '."'".$branch."'"
    if defined $branch && $branch !~ /^\d+\z/;

  if ( $self->kernel_module ne 'either' ) {
    my $module = $source->{kernel_module};
    return 0 unless defined $module && $module eq $self->kernel_module;
  }
  return 1 unless defined $self->min_branch || defined $self->max_branch;
  return 0 unless defined $branch;
  return 0 if defined $self->min_branch && $branch < $self->min_branch;
  return 0 if defined $self->max_branch && $branch > $self->max_branch;
  return 1;
}

=method intersect

  my $req = Rex::GPU::NVIDIA::Requirement->intersect(@requirements);
  my $req = $v100->intersect($b200);   # invocant included: croaks here

The one requirement that satisfies all given ones, for a host with several
GPUs: one driver has to drive them all. Called on an object, that object is
one of the requirements. The kernel module is the one any member insists on
(C<either> only if all say C<either>); C<min_branch> is the highest lower
bound, C<max_branch> the lowest upper bound. A single requirement comes back
unchanged; several give a new object whose L</members> lists them (nested
intersections flattened) and whose C<generation>, C<device_id> and C<name>
are C<undef>.

Croaks, naming the GPUs on each side, if members need different kernel
modules (a V100 needs C<proprietary>, a B200 C<open>) or the bounds leave no
branch (one GPU needs at least 590, another at most 580). Also croaks for an
empty list or anything that is not a requirement object.

=cut

sub intersect {
  my ( $self, @requirements ) = @_;
  unshift @requirements, $self if ref $self;
  croak __PACKAGE__.'->intersect needs at least one requirement'
    unless @requirements;
  for my $req ( @requirements ) {
    croak __PACKAGE__.'->intersect: not a '.__PACKAGE__.' object: '.( $req // 'undef' )
      unless blessed( $req ) && $req->isa( __PACKAGE__ );
  }
  return $requirements[0] if @requirements == 1;

  my @members = map { @{ $_->members } ? @{ $_->members } : $_ } @requirements;

  my %by_module;
  push @{ $by_module{ $_->kernel_module } }, $_ for @members;
  my ( $lower ) = sort { $b->min_branch <=> $a->min_branch }
    grep { defined $_->min_branch } @members;
  my ( $upper ) = sort { $a->max_branch <=> $b->max_branch }
    grep { defined $_->max_branch } @members;

  my @conflicts;
  push @conflicts, join( ', ', map { $_->_who } @{ $by_module{open} } )
      .' need'.( @{ $by_module{open} } == 1 ? 's' : '' ).' the open kernel module, but '
      .join( ', ', map { $_->_who } @{ $by_module{proprietary} } )
      .' need'.( @{ $by_module{proprietary} } == 1 ? 's' : '' ).' the proprietary one'
    if $by_module{open} && $by_module{proprietary};
  push @conflicts, $lower->_who.' needs driver branch '.$lower->min_branch
      .' or newer, but '.$upper->_who.' is supported only up to branch '.$upper->max_branch
    if $lower && $upper && $lower->min_branch > $upper->max_branch;
  croak __PACKAGE__.'->intersect: no single NVIDIA driver supports all GPUs on this host: '
    .join( '; ', @conflicts )
    if @conflicts;

  my $class = ref $self || $self;
  return $class->new(
    kernel_module => $by_module{open}        ? 'open'
                   : $by_module{proprietary} ? 'proprietary'
                   :                           'either',
    $lower ? ( min_branch => $lower->min_branch ) : (),
    $upper ? ( max_branch => $upper->max_branch ) : (),
    members => \@members
  );
}

=method describe

  print $req->describe;   # "open kernel module, driver branch 570 or newer"

A short human-readable form of the constraint, for log lines and error
messages.

=cut

sub describe {
  my ( $self ) = @_;
  my $module = $self->kernel_module eq 'either'
    ? 'any kernel module'
    : $self->kernel_module.' kernel module';
  my ( $min, $max ) = ( $self->min_branch, $self->max_branch );
  my $branch = defined $min && defined $max ? 'driver branch '.$min.' to '.$max
             : defined $min                 ? 'driver branch '.$min.' or newer'
             : defined $max                 ? 'driver branch '.$max.' or older'
             :                                'any driver branch';
  return $module.', '.$branch;
}

# "GV100GL [Tesla V100] (Maxwell/Pascal/Volta, 10de:1db4)" — who a member is,
# for conflict messages.
sub _who {
  my ( $self ) = @_;
  my @what = grep { defined } $self->generation,
    defined $self->device_id ? '10de:'.$self->device_id : undef;
  my $who = $self->name // 'NVIDIA GPU';
  return @what ? $who.' ('.join( ', ', @what ).')' : $who;
}

1;

=head1 SYNOPSIS

  use Rex::GPU::NVIDIA::Requirement;

  my $req = Rex::GPU::NVIDIA::Requirement->from_gpu($gpu);
  say $req->generation // 'unknown generation', ': ', $req->describe;

  $req->satisfied_by({ kernel_module => 'open', branch => 580 })
    or die "the -open 580 driver cannot drive this GPU\n";

  # several GPUs, one driver
  my $all = Rex::GPU::NVIDIA::Requirement->intersect(
    map { Rex::GPU::NVIDIA::Requirement->from_gpu($_) } @compute_gpus
  );

=head1 DESCRIPTION

B<Experimental.> This API may change without a deprecation cycle for one
release. L<Rex::GPU::NVIDIA>'s install paths do not use it yet — they still
choose the driver exactly as before; only
L<Rex::GPU::Detect/open_kernel_module_required> and
L<Rex::GPU::Detect/legacy_driver_requirement> read from it.

A requirement says which NVIDIA driver a GPU can work with: the kernel module
(L</kernel_module>) and the range of driver branches
(L</min_branch>..L</max_branch>). It is keyed on the PCI device ID, the one
signal C<lspci -nn> prints even when the host's C<pci.ids> predates the
silicon. Objects are immutable.

The table in L</generations> is a method, not a global, so a subclass can add
a row for silicon this release does not know yet without touching the
module.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA>, L<Rex::GPU::Detect>,
L<https://github.com/NVIDIA/open-gpu-kernel-modules>

=cut

# ABSTRACT: Rancher Kubernetes (RKE2/K3s) deployment automation for Rex

package Rex::Rancher;

use v5.14.4;
use warnings;

our $VERSION = '0.001';

use Rex::Rancher::Node;
use Rex::Rancher::Server;
use Rex::Rancher::Agent;
use Rex::Rancher::Cilium;
use Rex::GPU;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  rancher_deploy_server
  rancher_deploy_agent
);

=method rancher_deploy_server(%opts)

Full control plane deployment: prepare node, detect/install GPU drivers,
install Rancher K8s distribution, and set up Cilium CNI.

Options:

=over

=item C<distribution> — C<rke2> (default) or C<k3s>

=item C<hostname> — Node hostname (optional)

=item C<domain> — Domain name (optional)

=item C<timezone> — Timezone (default: C<UTC>)

=item C<locale> — Locale (default: C<en_US.UTF-8>)

=item C<ntp> — Enable NTP via chrony (default: C<1>)

=item C<token> — Cluster token (auto-generated if not provided)

=item C<version> — K8s version (auto-detected if not provided)

=item C<tls_san> — Additional TLS SAN for API server cert

=item C<node_name> — Node name override

=item C<registry_cache> — Pull-through cache URL

=item C<registry_upstream> — Upstream registry URL

=item C<registry_name> — Custom registry name

=back

=cut

sub rancher_deploy_server {
  my (%opts) = @_;
  my $distribution = $opts{distribution} // 'rke2';

  # 1. Prepare node
  prepare_node(%opts);

  # 2. GPU detection and setup
  gpu_setup(containerd_config => $distribution);

  # 3. Install server
  install_server(%opts);

  # 4. Install Cilium CNI
  install_cilium(distribution => $distribution);

  Rex::Logger::info("$distribution server deployment complete");
}

=method rancher_deploy_agent(%opts)

Full worker node deployment: prepare node, detect/install GPU drivers,
and join existing Rancher K8s cluster.

Options: Same as L</rancher_deploy_server> plus:

=over

=item C<server> — Server URL to join (required)

=item C<token> — Join token (required)

=back

=cut

sub rancher_deploy_agent {
  my (%opts) = @_;
  my $distribution = $opts{distribution} // 'rke2';

  # 1. Prepare node
  prepare_node(%opts);

  # 2. GPU detection and setup
  gpu_setup(containerd_config => $distribution);

  # 3. Join cluster
  install_agent(%opts);

  Rex::Logger::info("$distribution agent deployment complete");
}

1;

=head1 SYNOPSIS

  use Rex -feature => ['1.4'];
  use Rex::Rancher;

  # Deploy RKE2 control plane
  task "deploy_server", sub {
    rancher_deploy_server(
      distribution => 'rke2',
      hostname     => 'cp-01',
      domain       => 'k8s.example.com',
      tls_san      => 'k8s.example.com',
    );
  };

  # Deploy K3s worker
  task "deploy_worker", sub {
    rancher_deploy_agent(
      distribution => 'k3s',
      hostname     => 'worker-01',
      domain       => 'k8s.example.com',
      server       => 'https://10.0.0.1:6443',
      token        => 'K10...',
    );
  };

=head1 DESCRIPTION

L<Rex::Rancher> provides complete Kubernetes cluster deployment automation
for Rancher distributions (RKE2 and K3s) using the L<Rex> orchestration
framework.

Handles the full stack:

=over

=item Node preparation (hostname, NTP, sysctl, kernel modules)

=item GPU detection and NVIDIA driver/toolkit installation

=item Rancher K8s distribution installation (server or agent)

=item Cilium CNI deployment

=back

For fine-grained control, use the individual modules directly:

=over

=item L<Rex::Rancher::Node> — Node preparation

=item L<Rex::Rancher::Server> — Control plane installation

=item L<Rex::Rancher::Agent> — Worker node installation

=item L<Rex::Rancher::Cilium> — Cilium CNI management

=item L<Rex::GPU> — GPU detection and driver management

=back

=cut

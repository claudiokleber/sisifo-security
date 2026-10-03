# frozen_string_literal: true

# Runs one known Metasploit auxiliary against one HTTP origin.
# Captures its native report_service callback, not its human console output.
require 'json'
require 'uri'
require 'ipaddr'
require 'socket'

OUTPUT = '/tmp/metasploit.json'
PROFILE = 'auxiliary/scanner/http/http_version'
result = { schema_version: 1, module: PROFILE, status: 'failed', services: [] }
exit_code = 1
mod = nil

begin
  input = JSON.parse(ARGV.fetch(0))
  target = input.fetch('target')
  uri = URI.parse(target)
  raise 'Expected an HTTP(S) origin' unless %w[http https].include?(uri.scheme)
  raise 'Credentials, query and paths are not supported' if uri.userinfo || uri.query || uri.fragment || !['', '/'].include?(uri.path)
  host = uri.hostname
  raise 'Invalid host' if host.nil? || host.empty? || host.length > 253
  begin
    IPAddr.new(host)
  rescue IPAddr::InvalidAddressError
    raise 'Invalid hostname' unless host.split('.').all? { |label| label.match?(/\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z/) }
  end
  raise 'Invalid port' unless (1..65_535).cover?(uri.port)
  result[:target] = target
  # Resolve once in the tool network and pin the actual connection to that address.
  resolved = Addrinfo.getaddrinfo(host, uri.port, nil, :STREAM).map(&:ip_address).uniq
  raise 'No address resolved' if resolved.empty?
  resolved_host = resolved.first
  result[:resolved_hosts] = [resolved_host]

  require '/usr/src/metasploit-framework/config/boot'
  require 'msfenv'
  require 'msf/base'
  framework = Msf::Simple::Framework.create('DisableDatabase' => true)
  result[:framework_version] = Msf::Framework::Version
  mod = framework.modules.create(PROFILE)
  raise 'Metasploit HTTP version module unavailable' unless mod
  mod.datastore['RHOSTS'] = resolved_host
  mod.datastore['RHOST'] = resolved_host
  mod.datastore['RPORT'] = uri.port
  mod.datastore['SSL'] = uri.scheme == 'https'
  mod.datastore['VHOST'] = host
  mod.datastore['HttpClientTimeout'] = 15
  mod.datastore['ConnectTimeout'] = 10
  mod.datastore['THREADS'] = 1
  services = result[:services]
  mod.define_singleton_method(:report_service) do |options|
    # A nil fingerprint is not evidence of a responding HTTP service.
    info = options[:info].to_s.strip
    unless info.empty?
      services << { host: options[:host].to_s, port: options[:port].to_i,
                    protocol: options[:sname].to_s, info: info }
    end
  end
  mod.init_ui(nil, Rex::Ui::Text::Output::Stdio.new)
  mod.validate
  mod.setup
  # run_host is the native entry point for a single host in this scanner module.
  mod.run_host(resolved_host)
  raise 'No HTTP service evidence returned; inspect logs and connectivity' if services.empty?
  result[:status] = 'completed'
  exit_code = 0
rescue StandardError => e
  result[:error] = "#{e.class}: #{e.message}"
  warn result[:error]
ensure
  begin
    mod.cleanup if mod
  rescue StandardError => e
    result[:status] = 'failed'
    result[:error] = "Cleanup failed: #{e.message}"
    exit_code = 1
  end
  File.write(OUTPUT, JSON.pretty_generate(result))
end
exit exit_code

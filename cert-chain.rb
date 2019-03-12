require 'openssl'
require 'socket'

if ARGV.length < 1
  puts "Usage: cert-chain.rb <hostname> [<port>]"
  puts
  puts "\thostname:\tHost to connect to (without https://)"
  puts "\tport:\t\tPort to use to connect (default: 443)"
  exit 1
end

hostname = ARGV[0]
port = ARGV[1] ? ARGV[1] : 443

cert_chain = []

ssl_context = OpenSSL::SSL::SSLContext.new
ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
ssl_context.verify_callback = lambda do |preverify_ok, cert_store|
  return false unless preverify_ok # do what usually happens when bad cert
  cert_chain << cert_store.current_cert
  true
end

cert_store = OpenSSL::X509::Store.new
cert_store.set_default_paths

ssl_context.cert_store = cert_store

socket = OpenSSL::SSL::SSLSocket.new(TCPSocket.new(hostname, port), ssl_context).tap{|e| e.connect}

cert_chain.reverse.each do |cert|
  if socket.peer_cert_chain.include?(cert)
    puts "\e[32mSent by Server\e[0m: #{cert.subject.to_s}"
  else
    puts "\e[36mIn Trust Store\e[0m: #{cert.subject.to_s}"
  end
end
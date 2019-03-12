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
ssl_context.verify_callback = lambda do |verify_ok, cert_store|
  cert_chain << { cert: cert_store.current_cert, verify: verify_ok }
  verify_ok
end

cert_store = OpenSSL::X509::Store.new
cert_store.set_default_paths

ssl_context.cert_store = cert_store

socket = OpenSSL::SSL::SSLSocket.new(TCPSocket.new(hostname, port), ssl_context).tap{|e| e.connect}

cert_chain.reverse.each do |store|
  cert = store[:cert]
  verify = store[:verify]
  if socket.peer_cert_chain.include?(cert)
    puts "#{verify ? "👍" : "🔥"} \e[34mSent by Server\e[0m: #{cert.subject.to_s(OpenSSL::X509::Name::ONELINE)}"
  else
    puts "#{verify ? "👍" : "🔥"} \e[36mIn Trust Store\e[0m: #{cert.subject.to_s(OpenSSL::X509::Name::ONELINE)}"
  end
end
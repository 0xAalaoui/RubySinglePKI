require 'socket'
require 'openssl'

socket = TCPSocket.new('localhost', 2001)

ssl_context 			= OpenSSL::SSL::SSLContext.new
ssl_context.cert 		= OpenSSL::X509::Certificate.new(File.open("Entity/C2.crt"))
ssl_context.key 		= OpenSSL::PKey::RSA.new(File.open("Entity/C2.key"))
ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
ssl_context.ca_file		= 'CA/CA.crt'
ssl_socket 				= OpenSSL::SSL::SSLSocket.new(socket, ssl_context)

ssl_socket.connect

puts "[CLIENT] Connected"
ssl_socket.puts "client2"
puts "=> " + ssl_socket.gets
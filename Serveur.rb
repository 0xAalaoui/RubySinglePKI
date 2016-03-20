require 'thread'
require 'socket'
require 'openssl'
require 'base64'
$cipher = OpenSSL::Cipher.new("AES-256-ECB")

def encryption(msg,key)
	$cipher.encrypt
	$cipher.key = key
	crypt = $cipher.update(msg) + $cipher.final()
	crypt_string = (Base64.encode64(crypt))
	return crypt_string
end

socket = TCPServer.new('localhost', 2001)
keys = OpenSSL::PKey::RSA.new(File.open("End_Entity/Serveur.key"))

if not File.exist?('End_Entity/Serveur.crt')
	randomAESkey 		= $cipher.random_key	
	root_ca 	 	= OpenSSL::X509::Certificate.new(File.open("CA/CA.crt"))
	PubKey_CA		= root_ca.public_key
	aeskeyEncWithPubKeyCA	= PubKey_CA.public_encrypt(randomAESkey)
	aeskeyEncWithPubKeyCA 	= Base64.encode64(aeskeyEncWithPubKeyCA)
	socketWithCA 		= TCPSocket.new('localhost', 3000)
	puts "[SERVER] Waiting for certificate"
	socketWithCA.write aeskeyEncWithPubKeyCA #AES key encrypted with PubKey CA
	message = socketWithCA.recv(512) #Message from CA
	puts message
	pubKey = keys.public_key.to_s
	pubKeyEncWithAES = encryption(pubKey, randomAESkey) #PubKey encrypted with AES
	puts "[SERVER] Sending my encrypted public key"
	socketWithCA.write pubKeyEncWithAES
	certificate = socketWithCA.recv(2048) #Certificate from CA 				
	certificate = OpenSSL::X509::Certificate.new(certificate) 
	puts "[SERVER] Storing certificate"
	File.open 'End_Entity/Serveur.crt', 'w' do |io| io.write certificate.to_pem end
end


ssl_context 			= OpenSSL::SSL::SSLContext.new()
ssl_context.cert 		= OpenSSL::X509::Certificate.new(File.open("End_Entity/Serveur.crt"))
ssl_context.key 		= keys
ssl_context.verify_mode 	= OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
ssl_context.ca_file		= 'CA/CA.crt'
ssl_socket 			= OpenSSL::SSL::SSLServer.new(socket, ssl_context)


puts "[SERVER] Waiting for clients"
loop do
	begin
		Thread.start(ssl_socket.accept) do |s|
			 puts "[SERVER] Client connected"
			 identity = s.gets
			 s.puts "Bonjour " + identity
			 s.close
		 end
	rescue => e
	puts "ERREUR #{e.message}"
  end
end

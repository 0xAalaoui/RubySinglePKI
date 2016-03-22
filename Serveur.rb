require 'thread'
require_relative 'functions'

socketWithClients	= TCPServer.new('localhost', 2001)

myRSAKeypair 		= OpenSSL::PKey::RSA.new(File.open("End_Entity/Serveur.key"))
certificate_ca 		= OpenSSL::X509::Certificate.new(File.open("CA/CA.crt"))

if not File.exist?('End_Entity/Serveur.crt')
	socketWithCA    		= TCPSocket.new('localhost', 3000)
	
	randomAESkey 	        = $cipher.random_key 									#Random AES key
	PubKey_CA		        = certificate_ca.public_key								#PubKey CA
	aeskeyEncWithPubKeyCA	= PubKey_CA.public_encrypt(randomAESkey)				#Random AES key encrypted with PubKey CA
	aeskeyEncWithPubKeyCA 	= Base64.encode64(aeskeyEncWithPubKeyCA)				#Encode64
	
	puts "[SERVER] Waiting for certificate"
	socketWithCA.write aeskeyEncWithPubKeyCA 										#Sending to CA AES key encrypted with PubKey CA
	
	message = socketWithCA.recv(512)											    #Message from CA
	puts message
	
	pubKey = myRSAKeypair.public_key.to_s
	pubKeyEncWithAES = AESencryption(pubKey, randomAESkey) 							#PubKey encrypted with AES
	puts "[SERVER] Sending my encrypted public key"
	socketWithCA.write pubKeyEncWithAES
	
	encrypted_certificate = socketWithCA.recv(2048) 								#Certificate encrypted with AES 	
	certificate = AESdecryption(encrypted_certificate,randomAESkey)
	certificate = OpenSSL::X509::Certificate.new(certificate) 
	puts "[SERVER] Storing certificate"
	File.open 'End_Entity/Serveur.crt', 'w' do |io| io.write certificate.to_pem end #storing certificate to file
end


ssl_context 			= OpenSSL::SSL::SSLContext.new()
ssl_context.cert 		= OpenSSL::X509::Certificate.new(File.open("End_Entity/Serveur.crt"))
ssl_context.key 		= myRSAKeypair
ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
ssl_context.ca_file		= 'CA/CA.crt'
ssl_socket 				= OpenSSL::SSL::SSLServer.new(socketWithClients, ssl_context)


puts "[SERVER] Waiting for clients"
loop do
	begin
		Thread.start(ssl_socket.accept) do |s|
			identity = s.gets.chomp
			puts "[SERVER] " + identity + " connected"
			s.puts "Bonjour " + identity
			s.close
		 end
	rescue => e
	puts "ERREUR #{e.message}"
  end
end

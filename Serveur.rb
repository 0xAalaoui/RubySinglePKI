require 'thread'
require_relative 'functions'
pathCert 			= 'End_Entity/Serveur.crt' 						#Serveur certificate file
socketWithClients	= TCPServer.new('localhost', 2001)

myRSAKeypair 		= OpenSSL::PKey::RSA.new(File.open("End_Entity/Serveur.key"))


if not File.exist?(pathCert)										#if no certificate found, get one

	getCertificate(pathCert,myRSAKeypair, 3000)
	
end


ssl_context 			= OpenSSL::SSL::SSLContext.new()
ssl_context.cert 		= OpenSSL::X509::Certificate.new(File.open("End_Entity/Serveur.crt"))
ssl_context.key 		= myRSAKeypair
ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER 				#Accept if no certificate
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

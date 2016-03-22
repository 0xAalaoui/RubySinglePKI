require_relative 'functions'

socket = TCPServer.new('localhost', 3000)

loop do
	begin
		 Thread.start(socket.accept) do |s|
			puts "[CA] Client certifying..."	

			encrypted_AESkey = s.recv(1024) 						#AES key encrypted with CA PubKey
			puts "[CA] AES Key recieved"

			encrypted_AESkey = Base64.decode64(encrypted_AESkey)
			aesKey = $root_key.private_decrypt(encrypted_AESkey)

			s.write "[CA] Send your public key"

			encrypted_PUBkey = s.recv(1024) 						#Client's PubKey encrypted with AES
			puts "[CA] Public key recieved"

			pubKey = AESdecryption(encrypted_PUBkey,aesKey)
			pubKey = OpenSSL::PKey::RSA.new(pubKey)

			certificate 			= certify(pubKey) 				#Generate certificate for the client
			encrypted_certificate 	= AESencryption(certificate.to_s,aesKey)


			puts "[CA] Sending certificate"
			s.write encrypted_certificate
			s.close
			puts "[CA] Done"
		end
	 rescue => e
	 puts "Error #{e.message}"
   end
end

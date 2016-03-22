require_relative 'functions'

socket = TCPServer.new('localhost', 3000)
myRSAKeypair = OpenSSL::PKey::RSA.new(File.read('CA/CA.key'))

loop do
	begin
		 Thread.start(socket.accept) do |s|
			puts 	"[CA] Client certifying..."	

			encrypted_AESkey 	= s.recv(1024) 								#AES key encrypted with CA PubKey
			puts 	"[CA] AES Key recieved"

			encrypted_AESkey 	= Base64.decode64(encrypted_AESkey)
			aesKey 				= myRSAKeypair.private_decrypt(encrypted_AESkey)

			s.write "[CA] Send your public key"

			encrypted_PUBkey 	= s.recv(1024) 								#Client's PubKey encrypted with AES
			puts 	"[CA] Public key recieved"

			pubKey 				= AESdecryption(encrypted_PUBkey, aesKey) 	#Decrypt client's pubKey
			pubKey 				= OpenSSL::PKey::RSA.new(pubKey)

			certificate 		= certify(pubKey, myRSAKeypair) 			#Certificate for the client
			encrypted_certi 	= AESencryption(certificate.to_s, aesKey)	#Encrypted certificate with AES

			puts "[CA] Sending certificate"
			s.write encrypted_certi											#Sending the encrypted certificate
			s.close
			puts "[CA] Done"
		end
	 rescue => e
	 puts "Error #{e.message}"
   end
end

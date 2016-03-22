require 'socket'
require 'openssl'
require 'base64'

$cipher = OpenSSL::Cipher.new("AES-256-ECB")


def AESencryption(msg, key)
	$cipher.encrypt
	$cipher.key = key
	crypt = $cipher.update(msg) + $cipher.final()
	crypt_string = (Base64.encode64(crypt))
	return crypt_string
end

def AESdecryption(msg, key)
	$cipher.decrypt()
	$cipher.key = key
	tempkey = Base64.decode64(msg)
	crypt = $cipher.update(tempkey)
	crypt << $cipher.final()		
	return crypt
end

def certify(endEntityPubKey, caKey) #Certify function
	root_ca = OpenSSL::X509::Certificate.new(File.read('CA/CA.crt'))
	cert = OpenSSL::X509::Certificate.new
	cert.version = 2
	cert.serial = Random.rand(100000)
	cert.subject = OpenSSL::X509::Name.parse "/O=AalMokh Server/C=FR/CN=AalMokh CA"
	cert.issuer = root_ca.subject
	cert.public_key = endEntityPubKey
	cert.not_before = Time.now
	cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
	ef = OpenSSL::X509::ExtensionFactory.new
	ef.subject_certificate = cert
	ef.issuer_certificate = root_ca
	cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
	cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
	cert.sign(caKey, OpenSSL::Digest::SHA256.new)
	return cert
end

def getCertificate(path, myRSAKeypair, port)
	certificate_ca 		= OpenSSL::X509::Certificate.new(File.open("CA/CA.crt"))
	
	socketWithCA    		= TCPSocket.new('localhost', port)

	randomAESkey 	        = $cipher.random_key 									#Random AES key
	pubKey_CA		        = certificate_ca.public_key								#PubKey CA
	aeskeyEncWithPubKeyCA	= pubKey_CA.public_encrypt(randomAESkey)				#Random AES key encrypted with PubKey CA
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
	File.open path, 'w' do |io| io.write certificate.to_pem end #storing certificate to file




end
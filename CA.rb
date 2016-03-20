require 'socket'
require 'openssl'
require 'base64'
socket = TCPServer.new('localhost', 3000)

$root_key = OpenSSL::PKey::RSA.new(File.read('CA/CA.key'))
$cipher = OpenSSL::Cipher.new("AES-256-ECB")

def AESdecryption(msg, key)
	$cipher.decrypt()
	$cipher.key = key
	tempkey = Base64.decode64(msg)
	crypt = $cipher.update(tempkey)
	crypt << $cipher.final()		
	return crypt
end


def certify(rsaPubKey)
	root_ca = OpenSSL::X509::Certificate.new(File.read('CA/CA.crt'))
	cert = OpenSSL::X509::Certificate.new
	cert.version = 2
	cert.serial = Random.rand(100000)
	cert.subject = OpenSSL::X509::Name.parse "/O=AalMokh/C=FR/CN=AalMokh CA"
	cert.issuer = root_ca.subject
	cert.public_key = rsaPubKey
	cert.not_before = Time.now
	cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
	ef = OpenSSL::X509::ExtensionFactory.new
	ef.subject_certificate = cert
	ef.issuer_certificate = root_ca
	cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
	cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
	cert.sign($root_key, OpenSSL::Digest::SHA256.new)
	return cert
end

loop do
	begin
		 Thread.start(socket.accept) do |s|
			 puts "[CA] Client certifying..."	
			 
			 encrypted_AESkey = s.recv(1024) #AES key encrypted with CA PubKey
			 puts "[CA] AES Key recieved"
			 
			 encrypted_AESkey = Base64.decode64(encrypted_AESkey)
			 aesKey = $root_key.private_decrypt(encrypted_AESkey)
			 
			 s.write "[CA] Send your public key"
			 
			 encrypted_PUBkey = s.recv(1024) #Client's PubKey encrypted with AES
			 puts "[CA] Public key recieved"
			 
			 pubKey = AESdecryption(encrypted_PUBkey,aesKey)
			 pubKey = OpenSSL::PKey::RSA.new(pubKey)
			 
			 certificate = certify(pubKey) #Generate certificate for the client
			 
			 puts "[CA] Sending certificate"
			 s.write certificate
			 s.close
			 puts "[CA] Done"
		end
	 rescue => e
	 puts "Error #{e.message}"
   end
end

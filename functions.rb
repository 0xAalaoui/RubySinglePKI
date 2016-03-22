require 'socket'
require 'openssl'
require 'base64'

$root_key = OpenSSL::PKey::RSA.new(File.read('CA/CA.key'))
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


def certify(rsaPubKey)
	root_ca = OpenSSL::X509::Certificate.new(File.read('CA/CA.crt'))
	cert = OpenSSL::X509::Certificate.new
	cert.version = 2
	cert.serial = Random.rand(100000)
	cert.subject = OpenSSL::X509::Name.parse "/O=AalMokh Server/C=FR/CN=AalMokh CA"
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
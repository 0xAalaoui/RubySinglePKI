require 'openssl'

path_ca = ARGV[0]
root_key = OpenSSL::PKey::RSA.new(File.read(path_ca + '.key'))
root_ca = OpenSSL::X509::Certificate.new(File.read(path_ca + '.crt'))

key = OpenSSL::PKey::RSA.new 2048
cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = Random.rand(100000)
cert.subject = OpenSSL::X509::Name.parse "/O=AalMokh/C=FR/CN=AalMokh CA"
cert.issuer = root_ca.subject
cert.public_key = key.public_key
cert.not_before = Time.now
cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = root_ca
cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
cert.sign(root_key, OpenSSL::Digest::SHA256.new)

path_entity = ARGV[1]

File.open path_entity + '.crt', 'w' do |io| io.write cert.to_pem end
File.open path_entity + '.key', 'w' do |io| io.write key.to_pem end
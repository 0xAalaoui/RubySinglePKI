require 'openssl'

root_key = OpenSSL::PKey::RSA.new 1024 
root_ca = OpenSSL::X509::Certificate.new
root_ca.version = 2 
root_ca.serial = 1
root_ca.subject = OpenSSL::X509::Name.parse "/O=AalMokh/C=FR/CN=AalMokh CA"
root_ca.issuer = root_ca.subject 
root_ca.public_key = root_key.public_key
root_ca.not_before = Time.now
root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 
ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = root_ca
ef.issuer_certificate = root_ca
root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

path = ARGV[0]

File.open path + '.crt', 'w' do |io| io.write root_ca.to_pem end
File.open path + '.key', 'w' do |io| io.write root_key.to_pem end


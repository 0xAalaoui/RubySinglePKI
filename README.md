Use `create_CA.rb path/filename` to create the self-signed certificate + RSA key for the certification authority

Use `create_Entity.rb path_CA/filename path_entity/filename` to create th end-entity certificate + RSA key 

`CA.rb` is a small server used to certify the entity serveur 

`Serveur.rb` simple ssl server with certificate verification + get a certificate from CA if necessary

`Client1.rb & Client2.rb` simple ssl clients with certificate verification



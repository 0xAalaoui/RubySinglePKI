create_CA.rb path 					         => Generate auto signed certificate + key

create_Entity.rb path_CA path_entity => Generate end-entity certificate + key 

CA.rb 								               => CA file used to certify the entity serveur 

Serveur.rb 							             => simple ssl server with certificate verification + get a certificate from CA if necessary

Client1.rb & Client2.rb				       => simple ssl clients with certificate verification



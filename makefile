libssl_class.a:rsa_class.o
	ar cr libssl_class.a rsa_class.o
rsa_class.o:rsa_class.cpp rsa_class.h ssl_exception.h
	g++ -c rsa_class.cpp
debug:
	g++ -c rsa_class.cpp -g
	ar cr libssl_class.a rsa_class.o
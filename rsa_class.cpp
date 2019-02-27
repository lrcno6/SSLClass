#include<cstdio>
#include<cstring>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include"rsa_class.h"
#include"ssl_exception.h"
using namespace ssl_class;
RSAClass::PublicKey RSAClass::read_public_key(const char *file_name){
	FILE *file=fopen(file_name,"r");
	if(file==nullptr)
		throw SSLException("RSAClass::read_public_key: cannot open the file");
	RSA *pubkey=RSA_new();
	if(PEM_read_RSA_PUBKEY(file,&pubkey,nullptr,nullptr)==nullptr)
		throw SSLException("RSAClass::read_public_key: read the public key failed");
	return PublicKey(pubkey,this);
}
RSAClass::PrivateKey RSAClass::read_private_key(const char *file_name){
	FILE *file=fopen(file_name,"r");
	if(file==nullptr)
		throw SSLException("RSAClass::read_private_key: cannot open the file");
	RSA *prikey=RSA_new();
	if(PEM_read_RSAPrivateKey(file,&prikey,nullptr,nullptr)==nullptr)
		throw SSLException("RSAClass::read_private_key: read the private key failed");
	fclose(file);
	return PrivateKey(prikey,this);
}
std::string RSAClass::encrypt_with_public_key(const std::string &original,const PublicKey &pubkey)const{
	char *buffer=new char[pubkey.size()+1];
	int size=RSA_public_encrypt(original.size(),(const unsigned char*)original.c_str(),(unsigned char*)buffer,pubkey.get(),RSA_PKCS1_PADDING);
	if(size<0)
		throw SSLException("RSAClass::encrypt_with_public_key: encrypt failed");
	std::string ciphertext(buffer,size);
	delete[] buffer;
	return ciphertext;
}
std::string RSAClass::decrypt_with_public_key(const std::string &ciphertext,const PublicKey &pubkey)const{
	char *buffer=new char[pubkey.size()+1];
	int size=RSA_public_decrypt(ciphertext.size(),(const unsigned char*)ciphertext.c_str(),(unsigned char*)buffer,pubkey.get(),RSA_PKCS1_PADDING);
	if(size<0)
		throw SSLException("RSAClass::decrypt_with_public_key: decrypt failed");
	std::string original(buffer,size);
	delete[] buffer;
	return original;
}
std::string RSAClass::encrypt_with_private_key(const std::string &original,const PrivateKey &prikey)const{
	auto buffer=new char[prikey.size()+1];
	int size=RSA_private_encrypt(original.size(),(const unsigned char*)original.c_str(),(unsigned char*)buffer,prikey.get(),RSA_PKCS1_PADDING);
	if(size<0)
		throw SSLException("RSAClass::encrypt_with_private_key: encrypt failed");
	std::string ciphertext(buffer,size);
	delete[] buffer;
	return ciphertext;
}
std::string RSAClass::decrypt_with_private_key(const std::string &ciphertext,const PrivateKey &prikey)const{
	auto buffer=new char[prikey.size()+1];
	int size=RSA_private_decrypt(ciphertext.size(),(const unsigned char*)ciphertext.c_str(),(unsigned char*)buffer,prikey.get(),RSA_PKCS1_PADDING);
	if(size<0)
		throw SSLException("RSAClass::decrypt_with_private_key: decrypt failed");
	std::string original(buffer,size);
	delete[] buffer;
	return original;
}
#ifndef _RSA_CLASS_H_
#define _RSA_CLASS_H_
#include<string>
#include<cstdlib>
#include<openssl/rsa.h>
namespace ssl_class{
	class RSAClass{
		public:
			class Key;
			class PublicKey;
			class PrivateKey;
			RSAClass()noexcept:m_num(0){}
			~RSAClass()noexcept{
				clean();
			}
			void create_public_key(const std::string &prikey,const std::string &output)const noexcept{
				system(("openssl rsa -in "+prikey+" -pubout -out "+output).c_str());
			}
			void create_private_key(const std::string &output,size_t size)const noexcept{
				system(("openssl genrsa -out "+output+" "+std::to_string(size)).c_str());
			}
			PublicKey read_public_key(const char*);
			PublicKey read_public_key(const std::string&);
			PrivateKey read_private_key(const char*);
			PrivateKey read_private_key(const std::string&);
			std::string encrypt_with_public_key(const std::string&,const PublicKey&)const;
			std::string decrypt_with_public_key(const std::string&,const PublicKey&)const;
			std::string encrypt_with_private_key(const std::string&,const PrivateKey&)const;
			std::string decrypt_with_private_key(const std::string&,const PrivateKey&)const;
		private:
			size_t m_num;
			void add()noexcept{
				m_num++;
			}
			void sub()noexcept{
				if(--m_num==0)
					clean();
			}
			void clean()noexcept{
				CRYPTO_cleanup_all_ex_data(); 
			}
	};
	class RSAClass::Key{
		public:
			Key(const Key&)=delete;
			Key(Key &&other)noexcept:m_key(other.m_key),m_factory(other.m_factory){
				other.m_key=nullptr;
				other.m_factory=nullptr;
			}
			virtual ~Key()noexcept{
				RSA_free(m_key);
				if(m_factory!=nullptr)
					m_factory->sub();
			}
			Key& operator=(const Key&)=delete;
			Key& operator=(Key&&)=delete;
			RSA* get()const noexcept{
				return m_key;
			}
			int size()const noexcept{
				return RSA_size(m_key);
			}
		protected:
			Key(RSA *key,RSAClass *factory)noexcept:m_key(key),m_factory(factory){
				factory->add();
			}
			RSA *m_key;
			RSAClass *m_factory;
	};
	class RSAClass::PublicKey:public Key{
		friend class RSAClass;
		private:
			PublicKey(RSA *key,RSAClass *factory)noexcept:Key(key,factory){}
	};
	class RSAClass::PrivateKey:public Key{
		friend class RSAClass;
		private:
			PrivateKey(RSA *key,RSAClass *factory)noexcept:Key(key,factory){}
	};
	inline RSAClass::PublicKey RSAClass::read_public_key(const std::string &file_name){
		return read_public_key(file_name.c_str());
	}
	inline RSAClass::PrivateKey RSAClass::read_private_key(const std::string &file_name){
		return read_private_key(file_name.c_str());
	}
}
#endif
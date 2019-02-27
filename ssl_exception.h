#ifndef _SSL_EXCEPTION_H_
#define _SSL_EXCEPTION_H_
#include<string>
#include<exception>
namespace ssl_class{
	class SSLException:public std::exception{
		public:
			SSLException(const std::string &str):m_str(str){}
			SSLException(std::string &&str):m_str(str){}
			const char* what()const noexcept{
				return m_str.c_str();
			}
		private:
			std::string m_str;
	};
}
#endif
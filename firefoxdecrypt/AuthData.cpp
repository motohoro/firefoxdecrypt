#include "AuthData.h"



AuthData::AuthData()
	: username(0)
	, password(0)
	, hostname(0)
	, realm(0)
{
}


AuthData::~AuthData()
{
}

// http://ufcpp.net/study/miscprog/accessor.html#overload

char* AuthData::Username()
{
	return this->username;
}


void AuthData::Username(char* username)
{
	this->username = username;
}


char* AuthData::Password()
{
	return this->password;
}

void AuthData::Password(char * password)
{
	this->password = password;
}

char* AuthData::Hostname()
{
	return this->hostname;
}


void AuthData::Hostname(char* hostname)
{
	this->hostname = hostname;
}


char* AuthData::Realm()
{
	return this->realm;
}


void AuthData::Realm(char* realm)
{
	this->realm = realm;
}

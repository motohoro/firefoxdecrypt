#pragma once
class AuthData
{
public:
	AuthData();
	~AuthData();
private:
	char* username;
	char* password;
	char* hostname;
	char* realm;
public:
	char* Username();
	void Username(char* username);
	char* Password();
	void Password(char* password);
	char* Hostname();
	void Hostname(char* hostname);
	char* Realm();
	void Realm(char* realm);
};


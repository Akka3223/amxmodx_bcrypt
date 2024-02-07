#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <algorithm>
#include <cctype>
#include <string>

#include "main.h"
#include "amxxmodule.h"

#include <bcrypt.h>
#include "crypto/md5.hpp"
#include "crypto/sha1.hpp"
#include "crypto/sha256.hpp"
#include "crypto/sha3.hpp"
#include "crypto/crc32.hpp"
#include "crypto/keccak.hpp"
#include "crypto/base64.hpp"

int main()
{
    return 0;
}
//bcrypt(string[], len)
static cell AMX_NATIVE_CALL bcrypt_hash( AMX *amx, cell *params) 
{
    std::string StringtoCrypt = MF_GetAmxString(amx, params[1], 0, 0);
    std::string hash = bcrypt::generateHash(StringtoCrypt, params[4]);
    MF_SetAmxString(amx, params[2], hash.c_str(), params[3]);

    return 0;
}

static cell AMX_NATIVE_CALL bcrypt_validate( AMX *amx, cell *params) 
{
    std::string StringtoValidate = MF_FormatAmxString(amx, params, 1, 0);
    std::string HashedPass = MF_FormatAmxString(amx, params, 2, 0);
    bool newpass = bcrypt::validatePassword(StringtoValidate, HashedPass);

    return newpass;
}
static cell AMX_NATIVE_CALL Crypto_Hash(AMX* amx, cell* params) {
	enum args {
		arg_count,
		arg_hashType,
		arg_string,
		arg_result
	};

	int stringLength(0), hashTypeLength(0);

	auto hashType 	= MF_GetAmxString(amx, params[arg_hashType], 0, nullptr);
	auto string 	= MF_GetAmxString(amx, params[arg_string], 1, nullptr);

	std::string checkHashType(hashType);

	/*! Transform to case-insensitive for comparison */
	std::transform(checkHashType.begin(), checkHashType.end(), checkHashType.begin(), ::tolower);

	/*! Compare if we have found the algorithm */
	if (checkHashType == "md5") {
		MD5 hash;

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];
		
		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	}
	else if (checkHashType == "sha1") {
		SHA1 hash;
		std::string iStringifiedText(string);

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	} else if (checkHashType == "sha256") {
		SHA256 hash;
		std::string iStringifiedText(string);

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	} else if (checkHashType == "sha3") {
		SHA3 hash;
		std::string iStringifiedText(string);

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	} else if (checkHashType == "crc32") {
		CRC32 hash;
		std::string iStringifiedText(string);

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	}
	else if (checkHashType == "keccak") {
		Keccak hash;
		std::string iStringifiedText(string);

		auto hashedString = hash(std::string(string));
		char* test = &hashedString[0];

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	}
	else if (checkHashType == "base64") {
		BASE64 hash;
		std::string iStringifiedText(string);
		char ret[2048] = "\0";
		int len;
		hash.Encode(std::string(string).c_str(), std::string(string).size(), ret, &len);
		std::string hashedString(ret);

		MF_SetAmxString(amx, params[arg_result], hashedString.c_str(), hashedString.length());

		return 0;
	} else {
		std::string errMsg = "[" + std::string(MODULE_NAME) + "] Hash type '" + checkHashType + "' is not supported!\n";
		char* error = &errMsg[0];

		MF_PrintSrvConsole(error);

		return 1;
	}
	
	return -1;
}

AMX_NATIVE_INFO bcrypt_natives[] = 
{
    { "bcrypt", bcrypt_hash },
    { "bcrypt_validate", bcrypt_validate },
    { "crypto_hash", Crypto_Hash },
    { NULL, NULL }
};
void OnAmxxAttach()
{
    MF_AddNatives(bcrypt_natives);
}

void OnAmxxDetach()
{
    // This function is necessary, even if you have nothing to declare here. The compiler will throw a linker error otherwise.
    // This can be useful for clearing/destroying a handles system.
}

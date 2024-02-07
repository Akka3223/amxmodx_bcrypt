#if defined _bcrypt_included
	#endinput
#endif
#define _bcrypt_included

#pragma reqlib bcrypt_lib
#if !defined AMXMODX_NOAUTOLOAD
	#pragma loadlib bcrypt_lib
#endif

native bcrypt(string[], output[], len, rounds = 10);
native bcrypt_validate(string[], hash[]);
/*
Hash Types - 
	md5
	sha1
	sha256
	sha3
	crc32
	keccak
	base64
*/
native crypto_hash(const iHashType[], const iText[], const iResult[]);
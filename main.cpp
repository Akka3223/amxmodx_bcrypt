#include <stdlib.h>
#include <string>
#include <stdio.h>

#include "main.h"
#include "amxxmodule.h"

#include <bcrypt.h>

int main()
{
    return 0;
}
//bcrypt(string[], len)
static cell AMX_NATIVE_CALL bcrypt_hash( AMX *amx, cell *params) 
{
    std::string StringtoCrypt = MF_GetAmxString(amx, params[1], 0, 0);
    
    MF_PrintSrvConsole(StringtoCrypt.c_str());

    std::string hash = bcrypt::generateHash(StringtoCrypt, params[4]);

    MF_PrintSrvConsole(hash.c_str());
    MF_SetAmxString(amx, params[2], hash.c_str(), params[3]);
    // This will print "pFullMsg" in the server console.

    return 0;
}

static cell AMX_NATIVE_CALL bcrypt_validate( AMX *amx, cell *params) 
{
    std::string StringtoValidate = MF_FormatAmxString(amx, params, 1, 0);
    std::string HashedPass = MF_FormatAmxString(amx, params, 2, 0);
    // We declared a char pointer, and gave it a value.
    // The value is, a formatted string returned from "MF_FormatAmxString", a function similar to "sprintf".
    bool newpass = bcrypt::validatePassword(StringtoValidate, HashedPass);

    return newpass;
}
AMX_NATIVE_INFO bcrypt_natives[] = 
{
    { "bcrypt", bcrypt_hash },
    { "bcrypt_validate", bcrypt_validate },
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

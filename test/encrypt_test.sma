#include <amxmodx>
#include <bcrypt>

public plugin_init()
{
	register_plugin("bcrypt test", "1.0", "Akka");
    register_clcmd("bcrypt", "handle_bcrypt");
    register_clcmd("bcrypt_validate", "handle_bcrypt_validate");
    register_clcmd("crypto", "handle_crypto");
}
public handle_crypto(id)
{
    static arg[2][64];
    read_argv(1, arg[0], charsmax(arg[]));
    read_argv(2, arg[1], charsmax(arg[]));

    if(arg[0][0] && arg[1][0])
    {
        static bcrypted[256];
        new iSuccess = crypto_hash(arg[0], arg[1], bcrypted);
        if(iSuccess == 0)
            console_print(id, "crypto_hash [%s] result: %s", arg[0], bcrypted);
        else
            console_print(id, "crypto_hash fail, invalid hashtype?");
        console_print(id, "Hash Types: md5, sha1, sha256, sha3, crc32, keccak, base64.");
    }
    else
    {
        console_print(id, "crypto <hashtype> <string to encrypt>");
        console_print(id, "Hash Types: md5, sha1, sha256, sha3, crc32, keccak, base64.");
    }
}
public handle_bcrypt(id)
{
    static arg1[64];
    read_argv(1, arg1, charsmax(arg1));
    if(arg1[0])
    {
        static bcrypted[64];
        bcrypt(arg1, bcrypted, charsmax(bcrypted), 10);
        console_print(id, "BCrypt result: %s", bcrypted);
    }
    else
    {
        console_print(id, "bcrypt <string to encrypt>");
    }
    
}
public handle_bcrypt_validate(id)
{
    static arg[2][64];
    read_argv(1, arg[0], charsmax(arg[]));
    read_argv(2, arg[1], charsmax(arg[]));
    if(arg[0][0] && arg[1][0])
    {
        if(bcrypt_validate(arg[0], arg[1]))
        {
            console_print(id, "Validated");
        }
        else
        {
            console_print(id, "Invalid");
        }
    }
    else
    {
        console_print(id, "bcrypt_validate <string> <bcrypts generated hash>");
        console_print(id, "------- EXAMPLE -------");
        console_print(id, "bcrypt asd = $2b$10$crwtn0SeCh9PBAQqrCotjeiaFBqUIG/PmckfAUr4cNN8.T9ACAEvG");        
        console_print(id, "bcrypt_validate asd $2b$10$crwtn0SeCh9PBAQqrCotjeiaFBqUIG/PmckfAUr4cNN8.T9ACAEvG will output validated.");
    }
}
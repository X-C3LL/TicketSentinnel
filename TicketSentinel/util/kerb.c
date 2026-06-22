#include <stdio.h>
#include <krb5.h>

#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif


int copy_to_ccache(char *filename) {
    krb5_context ctx;
    krb5_ccache src, dst;
    krb5_principal princ;
    char dest[256];

    if (krb5_init_context(&ctx)) {
        DBG("[!] ERROR! krb5_init_context failed!\n");
        return -1;
    }

    if (krb5_cc_default(ctx, &src)) {
        DBG("[!] ERROR! krb5_cc_default failed!\n");
        return -2;
    }

    snprintf(dest,sizeof(dest),"FILE:%s", filename);
    
    if(krb5_cc_resolve(ctx, dest, &dst)){
        DBG("[!] ERROR! krb5_cc_resolve failed!\n");
        return -3;
    }

    if(krb5_cc_get_principal(ctx, src, &princ)){
        DBG("[!] ERROR! krb5_cc_get_principal failed!\n");
        return -4;
    }

    if(krb5_cc_initialize(ctx, dst, princ)){
        DBG("[!] ERROR! krb5_cc_initialize failed!\n");
        return -5;
    }

    if(krb5_cc_copy_creds(ctx, src, dst)){
        DBG("[!] ERROR! krb5_cc_copy_creds failed!\n");
    return -6;
    }


    DBG("[*] Ticket copied to  %s\n", filename);


    krb5_free_principal(ctx, princ);
    krb5_cc_close(ctx, src);
    krb5_cc_close(ctx, dst);
    krb5_free_context(ctx);
    return 0;

}

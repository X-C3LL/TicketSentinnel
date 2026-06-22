#include <stdio.h>
#include <stdlib.h>
#include <krb5.h>
#include "tickets.h"


#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif

void setTicket(char* filename) {
	setenv("KRB5CCNAME", filename, 1);
}

void unsetTicket(void) {
	unsetenv("KRB5CCNAME");
}

char *getPrincipal(char* filename){
	krb5_context context;
	krb5_ccache cache;
	krb5_cccol_cursor cursor;
	krb5_error_code ret;
	krb5_principal princ = NULL;
	char *princname = NULL;

	//Use ticket
	setTicket(filename);
	
	//Initiate context
	ret = krb5_init_context(&context);
	if (ret) {
		DBG("[!] ERROR: Could not initate krb5 context!\n");
		return NULL;
	}
	ret = krb5_cccol_cursor_new(context, &cursor);
	if (ret){
		DBG("[!] ERROR: Could not obtain cursor!\n");
		return NULL;
	}
	while ((ret = krb5_cccol_cursor_next(context, cursor, &cache)) == 0 &&
           cache != NULL) {
		ret = krb5_cc_get_principal(context, cache, &princ);
		if (ret){
			krb5_free_principal(context, princ);
			krb5_cc_close(context, cache);
			continue;
		}
		ret = krb5_unparse_name(context, princ, &princname);
		if (ret){
                        krb5_free_principal(context, princ);
			krb5_free_unparsed_name(context, princname);
			krb5_cc_close(context, cache);
                        continue;
                }
		DBG("[*] Principal Name: %s\n", princname);
		krb5_cc_close(context, cache);
	}
	krb5_cccol_cursor_free(context, &cursor);
	//Revert
	unsetTicket();
	return princname;
}

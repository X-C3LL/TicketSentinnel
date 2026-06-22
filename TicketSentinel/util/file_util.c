#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "file_util.h"

#define DEBUG

int readFileToBuf(char *path, char **out_buf, size_t *out_len) {
	FILE *fp = NULL;
	    struct stat st;
	    char *buf;

	    if (!path || !out_buf || !out_len)
		return -1;

	    *out_buf = NULL;
	    *out_len = 0;

	    if (stat(path, &st) != 0)
		return -2;

	    if (st.st_size == 0)
		return -3;

	    fp = fopen(path, "rb");
	    if (!fp)
		return -4;

	    buf = malloc(st.st_size);
	    if (!buf) {
		fclose(fp);
		return -5;
	    }

    	if (fread(buf, 1, st.st_size, fp) != (size_t)st.st_size) {
		free(buf);
		fclose(fp);
		return -6;
    	}

    	fclose(fp);

    	*out_buf = buf;
    	*out_len = (size_t)st.st_size;
	return 0;
}

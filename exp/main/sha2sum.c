#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "psa/crypto.h"
#include "aliases.h"

#define HASH_SZ PSA_HASH_SIZE(PSA_ALG_SHA_256)

int compute_sha(char * filename, uint8_t * h)
{
    struct stat fileinfo ;
    void *      buf ;
    int         fd ;
    size_t      written;

    psa_hash_operation_t    ctx ;

    /* Mmap input file */
    if (stat(filename, &fileinfo)!=0) {
        perror("stat");
        return -1;
    }
    if ((fd=open(filename, O_RDONLY))==-1) {
        perror("open");
        return -1 ;
    }
    buf = mmap(0,
               fileinfo.st_size,
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE,
               fd,
               0);
    close(fd);
    if (buf==(void*)-1) {
        perror("mmap");
        return -1 ;
    }

    /* Compute SHA */
    memset(&ctx, 0, sizeof(psa_hash_operation_t));
    psa_hash_compute(PSA_ALG_SHA_256,
                     buf,
                     fileinfo.st_size,
                     h,
                     PSA_HASH_SIZE(PSA_ALG_SHA_256),
                     &written);

    /* Unmap file */
    if (munmap(buf, fileinfo.st_size)!=0) {
        perror("munmap");
    }
    return 0 ;
}

int main(int argc, char * argv[])
{
    uint8_t h[HASH_SZ];
    int     err ;
    int     i, j ;

	if (argc<2) {
		printf("use: %s filename(s)\n", argv[0]);
		return 1 ;
	}

    for (i=1; argv[i]; i++) {
        memset(h, 0, HASH_SZ);
        err = compute_sha(argv[i], h);
        if (!err) {
            for (j=0 ; j<HASH_SZ ; j++) {
                printf("%02x", h[j]);
            }
            printf("\t%s\n", argv[i]);
        }
    }
	return 0 ;
}


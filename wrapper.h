#include<libipset/ipset.h>

extern int rust_error_callback(struct ipset *ipset, void* p, int status, const char *msg);

extern int error_callback(struct ipset *ipset, void *p,
                            int status, const char *msg, ...);

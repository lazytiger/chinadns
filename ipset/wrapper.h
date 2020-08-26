#include<libipset/ipset.h>
#include<libipset/session.h>

extern int rust_error_callback(struct ipset *ipset, void* p, int status, const char *msg);
extern int rust_session_callback(struct ipset_session *session, void* p, const char *msg);

extern int error_callback(struct ipset *ipset, void *p,
                            int status, const char *msg, ...);
extern int session_callback(struct ipset_session *session, void *p,
                          const char *msg, ...);

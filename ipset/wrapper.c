//
// Created by hoping on 8/25/20.
//
#include "wrapper.h"
#include<stdarg.h>

int error_callback(struct ipset *ipset, void *p,
                  int status, const char *msg, ...)
{
    char message[1024];
    va_list args;
    va_start(args, msg);
    int size = vsprintf(message, msg, args);
    message[size] = 0;
    return rust_error_callback(ipset, p, status, message);
}

int session_callback(struct ipset_session *session, void *p,
                    const char *msg, ...)
{
    char message[1024];
    va_list args;
    va_start(args, msg);
    int size = vsprintf(message, msg, args);
    message[size] = 0;
    return rust_session_callback(session, p, message);
}

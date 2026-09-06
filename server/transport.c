#include <string.h>
#include "transport.h"
 
extern transport_t TRANSPORT_TCP;
extern transport_t TRANSPORT_HTTP;
extern transport_t TRANSPORT_HTTPS;
 
static transport_t *transports[] = {
    &TRANSPORT_TCP,
    &TRANSPORT_HTTP,
    &TRANSPORT_HTTPS,
    NULL
};
 
transport_t *transport_get(const char *name)
{
    for (int i = 0; transports[i] != NULL; i++) {
        if (strcmp(transports[i]->name, name) == 0)
            return transports[i];
    }
    return NULL;
}
 
 
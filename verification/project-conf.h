#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC                 nullrdc_driver
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC                 nullmac_driver
#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM                 5
#undef LLSEC802154_CONF_SECURITY_LEVEL
#define LLSEC802154_CONF_SECURITY_LEVEL   2
#define APKES_CONF_SCHEME                 leap_apkes_scheme
#include "net/llsec/coresec/coresec-autoconf.h"

CONTIKI_PROJECT = verification
all: $(CONTIKI_PROJECT)

CONTIKI = ..
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

WITH_UIP6=1
UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL

include $(CONTIKI)/Makefile.include





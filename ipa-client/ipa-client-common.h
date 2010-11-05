#ifndef __IPA_CLIENT_COMMON_H
#define __IPA_CLIENT_COMMON_H

#include <libintl.h>
#define _(STRING) gettext(STRING)

int init_gettext(void);

#endif /* __IPA_CLIENT_COMMON_H */

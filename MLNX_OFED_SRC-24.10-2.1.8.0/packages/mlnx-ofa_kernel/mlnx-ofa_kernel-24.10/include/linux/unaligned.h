#ifndef _COMPAT_LINUX_UNALIGNED_H
#define _COMPAT_LINUX_UNALIGNED_H


/* Include the autogenerated header file */
#include "../../compat/config.h"

#if defined (HAVE_LINUX_UNALIGNED_H)
#include_next<linux/unaligned.h>
#else
#include <asm/unaligned.h>
#include <asm-generic/unaligned.h>
#endif

#endif /* _COMPAT_LINUX_UNALIGNED_H */

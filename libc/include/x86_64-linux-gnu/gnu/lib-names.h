/* This file is automatically generated.
   It defines macros to allow user program to find the shared
   library files which come as part of GNU libc.  */
#ifndef __GNU_LIB_NAMES_H
#define __GNU_LIB_NAMES_H	1

#if !defined __x86_64__
# include <gnu/lib-names-32.h>
#endif
#if defined __x86_64__ && defined __LP64__
# include <gnu/lib-names-64.h>
#endif
#if defined __x86_64__ && defined __ILP32__
# include <gnu/lib-names-x32.h>
#endif

#endif	/* gnu/lib-names.h */
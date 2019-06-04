#ifndef _builtin_h_
#define _builtin_h_

#include "parse.h"

int is_builtin (char* cmd);
void builtin_execute (Task T);
void builtin_which (char* exe);

#endif /* _builtin_h_ */

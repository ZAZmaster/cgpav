#ifndef XSIGNAL_H
#define XSIGNAL_H

#include <sys/types.h>
#include <signal.h>

void (*xsignal (int, void (*) (int))) (int);	/* my signal() analogue.
						   it uses sigaction() to
						   achieve best reliability */

#endif

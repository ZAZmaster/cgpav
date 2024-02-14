/* $Id: xsignal.c, v 1.5 2010/07/01 12:00:00 farit Exp $ */

#include "xsignal.h"

/* this function simulates signal(3) using sigaction(2) to achieve
 * better reliability */
void (*xsignal(int signo, void (*hndlr) (int))) (int)
{
    struct sigaction act, oact;

    act.sa_handler = hndlr;	/* set handlig function */
    sigemptyset(&act.sa_mask);	/* empty signal mask */
    act.sa_flags = 0;		/* empty flags */

    if (signo != SIGALRM)
	act.sa_flags |= SA_RESTART;	/* restart some syscalls
					   after signal handling */

    if (signo == SIGCHLD)
	act.sa_flags |= SA_NOCLDSTOP;	/* generate signal _only_
					   when child exited */

    if (sigaction(signo, &act, &oact) < 0)
	return SIG_ERR;

    return oact.sa_handler;
}

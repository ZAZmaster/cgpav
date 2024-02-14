#ifndef __MYSQLCOMM_H
#define __MYSQLCOMM_H

#include <stdio.h>
#include <string.h>
#include <mysql.h>

#include "cfg.h"

extern struct settings *sett;


/* get a user having settings in the database */
int get_db_user(MESSAGE *mess);


#endif

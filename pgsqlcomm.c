/* $Id: pgsqlcomm.c, v 1.5 2010/07/01 12:00:00 farit Exp $ */

#include "pgsqlcomm.h"


static void db_disconnect(PGconn *conn)
{
    if (!conn)
        return;
        
    PQfinish(conn);
    conn = NULL;
}


static PGconn *db_connect(void)
{
    /* PostgreSQL descriptor */
    PGconn *conn;
    char *port = NULL;

    if (!sett->db_username || !sett->db_password)
      return NULL;
    
    if (sett->db_database 
        && (strcasecmp(sett->db_database, "localhost") == 0)) {
        free(sett->db_database);
        sett->db_database = NULL;
    }            
    
    if (sett->db_port && (sett->db_port > 0)) {
        if (!(port = (char *)malloc(21)))
            return NULL;
        sprintf(port, "%d", sett->db_port);    
    }
    
    /* make a connection to the database */
    conn = PQsetdbLogin(sett->db_host, port, NULL, NULL, 
                    sett->db_database, sett->db_username, sett->db_password);
    
    if (port)
        free(port);
    
    if (PQstatus(conn) == CONNECTION_BAD) {
#ifdef DEBUG    
        printf("Connection to the database failed.\n");
        printf("%s\n", PQerrorMessage(conn));
#endif        
        db_disconnect(conn);    
        return NULL;
    }    

    return conn;
}

/* get a user who has settings in the database */
int get_db_user(MESSAGE *mess)
{
    PGconn *conn;
    PGresult *result;
    char *sql = NULL;
    char *tmp = NULL;


    if (!mess)
        return -1;
        
    /* no message recipients */
    if (mess->recipients->size <= 0)
        return 0;
        
    /* initialise response */
    mess->user_spam_action = 0;
    mess->user = NULL;        

    conn = db_connect();
    if (!conn)
        return -1;

    /* list of recipients */	
    tmp = join_vector("' OR username='", mess->recipients);
    /* no recipients */
    if (!tmp) {
        db_disconnect(conn);
        return 0;
    }    
	
    /* sql query */
    sql = (char *)malloc(strlen("SELECT username, value FROM userpref")
	    + strlen(" WHERE preference='spamcgpd_action' AND (username='")
	    + strlen(tmp) + strlen("') LIMIT 1") + 1);
    if (!sql) {
	if (tmp)
	    free(tmp);
            
	db_disconnect(conn);	
	return -1;
    }        
    sprintf(sql, "SELECT username, value FROM userpref"
		 " WHERE preference='spamcgpd_action'"
		 " AND (username='%s') LIMIT 1",
	    tmp);
#ifdef DEBUG
    printf("SQL query: %s\n", sql);
#endif
	
    if (tmp)
	free(tmp);	     	

    result = PQexec(conn, sql);

    if (sql)
        free(sql);
    
    if (!result) {
#ifdef DEBUG    
        printf("SELECT command failed, no error code\n");
#endif        
        db_disconnect(conn);
        return -1;
    }    
    else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
#ifdef DEBUG    
        printf("SELECT failed with code %s, error message %s\n",
                PQresStatus(PQresultStatus(result)),
                PQresultErrorMessage(result));
#endif                    
        PQclear(result);
        db_disconnect(conn);                        
        return -1;
    }
    
    /* something was found */
    if (PQntuples(result) >= 1) {
        if (!PQgetisnull(result, 0, 0))
            mess->user = strdup(PQgetvalue(result, 0, 0));
        if (!PQgetisnull(result, 0, 1))
            mess->user_spam_action = atoi(PQgetvalue(result, 0, 1));
#ifdef DEBUG
        printf("AntiSpam user: %s\n", mess->user);
        printf("AntiSpam user action: %d\n", mess->user_spam_action);
#endif        
                
    }
                              
    if (result)
        PQclear(result);
        
    db_disconnect(conn);        

    return 0;
}

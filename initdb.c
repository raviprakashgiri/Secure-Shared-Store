#include <my_global.h>
#include <mysql.h>

void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);        
}

int main(int argc, char **argv)
{
  MYSQL *con = mysql_init(NULL);
  
  if (con == NULL) 
  {
      fprintf(stderr, "%s\n", mysql_error(con));
      exit(1);
  }  

  if (mysql_real_connect(con, "localhost", "project2user", argv[1], 
          "filedata", 0, NULL, 0) == NULL) 
  {
      finish_with_error(con);
  }    
  
  if (mysql_query(con, "DROP TABLE IF EXISTS Files")) {
      finish_with_error(con);
  }
  
  if (mysql_query(con, "CREATE TABLE Files(Id INT PRIMARY KEY AUTO_INCREMENT, Name TEXT, Security TEXT, Location TEXT, Owner TEXT, Delegations INT, CheckedOut BOOL)")) {      
      finish_with_error(con);
  }
  
  if (mysql_query(con, "INSERT INTO Files VALUES(1,'testfile1.txt','NONE','./client1/testfile1.txt','user1',0,FALSE)")) {
      finish_with_error(con);
  }

  if (mysql_query(con, "INSERT INTO Files VALUES(2, 'testfile2.txt','NONE','./client1/testfile2.txt','client',0,FALSE)")) {
      finish_with_error(con);
  }

  if (mysql_query(con, "INSERT INTO Files(Name) VALUES('testfile3.txt')")) {
      finish_with_error(con);
  }

  mysql_close(con);
  exit(0);
}


# the compiler: gcc for C program
CXX = gcc
RM = rm -rf

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
#  CFLAGS  = -g -Wall

# the build target executable:
SERVER = server
SOURCE_SERVER = server.c
CLIENT = client
SOURCE_CLIENT = client.c
DATABASE = initdb
SOURCE_DATABASE = initdb.c

all: $(SERVER) $(CLIENT) $(DATABASE)

$(SERVER):
	$(CXX) $(SOURCE_SERVER) `mysql_config --cflags --libs` -lssl -lcrypto -o $(SERVER)

$(CLIENT):
	$(CXX) $(SOURCE_CLIENT) -lssl -lcrypto -lm -o $(CLIENT)

$(DATABASE): 
	$(CXX) $(SOURCE_DATABASE) -o $(DATABASE) -std=c99 `mysql_config --cflags --libs`

clean:
	$(RM) $(SERVER) $(CLIENT) $(DATABASE) 

#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<unistd.h> 
#include<sys/types.h> 
#include<sys/socket.h> 
#include<netinet/in.h>

void error(const char *msg){ perror(msg); exit(1); } //error function for reporting to stderr

//source: server.c from the class website
int main(int argc, char *argv[]){
	
	int listenSocketFD, estConnFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	char plaintext[100000], ciphertext[100000], key[100000];
	struct sockaddr_in serverAddr, clientAddr;
	int i; //loop counter
	pid_t childPID = -5;
	pid_t childPIDS[5]; //store child PIDS for cleanup
	int counter = 0; //number of child processes
	int childExitMethod = 0;
	
	if(argc < 2)
		{fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1);}
		
	//set up the network socket to listen on
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
	if(listenSocketFD < 0)
		error("ERROR opening socket");
	
	//set up address struct for this daemon
	memset((char *)&serverAddr, '\0', sizeof(serverAddr)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddr.sin_family = AF_INET; // Create a network-capable socket
	serverAddr.sin_port = htons(portNumber); // Store the port number
	serverAddr.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process
	
	//bind socket to port 
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
		error("ERROR on binding");
	//enable listening on port: will queue up to 5 connection requests
	if (listen(listenSocketFD, 5) < 0)
		error("ERROR on listen");
	
	//loop and accept connections, connecting them to new sockets/processes
	while(1){
		fflush(stdout);
		
		//check for concurrent child process completion
		for(i=0; i<counter; i++){
			int res = waitpid(childPIDS[i], &childExitMethod, WNOHANG);
			if(res){
				counter--;
				int j;
				//remove finished process id from array
				for(j=i; j<counter; j++){
					childPIDS[j] = childPIDS[j+1];
				}
			}
		}
		
		sizeOfClientInfo = sizeof(clientAddr);
		estConnFD = accept(listenSocketFD, (struct sockaddr *)&clientAddr, &sizeOfClientInfo);
		if(estConnFD < 0)
			fprintf(stderr, "ERROR on accept\n");
		//do encryption in child process
		childPID = fork();
		if(childPID == -1){
			fprintf(stderr, "ERROR: fork\n");
		}
		//this is the child process where encoding occurs
		else if(childPID == 0){ 
			//get id validation from client
			int charsSent;
			char id[4];
			memset(id, '\0', sizeof(id));
			charsRead = recv(estConnFD, id, 3, 0);
			if (charsRead < 0) 
				fprintf(stderr, "ERROR reading from socket\n");
			//if client is validated, respond affirmatively
			if(!strcmp(id, "ENC")){
				memset(id, '\0', sizeof(id));
				strcpy(id, "OK");
				charsSent = send(estConnFD, id, strlen(id), 0); // Write identifier to the server
				if (charsSent < 0) fprintf(stderr, "CLIENT: ERROR writing text to socket\n");
				if (charsSent < strlen(id)) fprintf(stderr, "CLIENT: WARNING: Not all text data written to socket!\n");
			}
			//reject connection if client not recognized and terminate process
			else{
				memset(id, '\0', sizeof(id));
				strcpy(id, "NO");
				charsSent = send(estConnFD, id, strlen(id), 0); // Write identifier to the server
				if (charsSent < 0) fprintf(stderr, "CLIENT: ERROR writing text to socket\n");
				if (charsSent < strlen(id)) fprintf(stderr, "CLIENT: WARNING: Not all text data written to socket!\n");
				return 0;
			}
		
			//get message from client, read until termination character '$' found
			memset(plaintext, '\0', sizeof(plaintext));
			char buffer[1000];
			charsRead = 0;
			int n;
			while(!strstr(plaintext, "$")){
				memset(buffer, '\0', sizeof(buffer));
				n = recv(estConnFD, buffer, sizeof(buffer)-1, 0);
				if (n < 0) 
					fprintf(stderr, "ERROR reading from socket\n");
				charsRead += n;
			//	printf("Buffer in server length %d %d\n", n, strlen(buffer));
				strcat(plaintext, buffer);
				usleep(2000);
			}
		//	printf("Buffer: %s\n", buffer);
		//	printf("chars read: %d, strlen: %d\n", charsRead, strlen(plaintext));
//printf("%s\n", plaintext);
		charsRead = strlen(plaintext);
//printf("SERVER: length = %d\n", charsRead); 

			//get key from client, read until termination character '$' found
			memset(key, '\0', sizeof(key));
			while(!strstr(key, "$")){
				memset(buffer, '\0', sizeof(buffer));
				n = recv(estConnFD, buffer, sizeof(buffer)-1, 0);
				if (n < 0) 
					fprintf(stderr, "ERROR reading from socket\n");
				strcat(key, buffer);
				usleep(2000);
			}
						
			//encode message
			//convert plaintext chars to ints: A-Z are 0-25 and space is 26
			//ignore termination character
			for(i=0; i<charsRead-1; i++){
				if(plaintext[i] == 32)
					plaintext[i] = 26;
				else plaintext[i] -= 65;			
			}
			//convert key chars to ints
			for(i=0; i<charsRead-1; i++){
				if(key[i] == 32)
					key[i] = 26;
				else key[i] -= 65;			
			}

			//add key to plaintext with modulo 27, convert to ascii		
			memset(ciphertext, '\0', sizeof(ciphertext));
			for(i=0; i<charsRead-1; i++){
				ciphertext[i] = key[i] + plaintext[i];
				//modulo 27
				if(ciphertext[i] > 26)
					ciphertext[i] -= 27;
				//convert to ascii (26 is space char)
				if(ciphertext[i] == 26)
					ciphertext[i] = 32;
				else
					ciphertext[i] += 65;
			}
			strcat(ciphertext, "$");
		//	printf("   %s\n", ciphertext);
			
			//send encoded message back to client
			int len = strlen(ciphertext);
			int total = 0;
			while(total<len){
				charsSent = send(estConnFD, ciphertext+total, 999, 0); // Write to the client
				if (charsSent < 0) fprintf(stderr, "SERVER: ERROR writing text to socket\n");
				total += charsSent;
			}
			if (total < len) fprintf(stderr, "SERVER: WARNING: Not all text data written to socket\n");
			
			// Close the existing socket which is connected to the client
			close(estConnFD); 
			return 0; //end child process
		}
		else{ //parent process
			//store childPID for cleanup
			childPIDS[counter] = childPID;
			counter++;
		}
	}
	close(listenSocketFD);
	return 0;
}
	
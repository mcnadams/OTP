#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include<fcntl.h>

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char text[100000], key[100000]; //stores data to send to otp_enc_d and store data sent back
	int plainTextFD, keyFD; //file descriptors for inputs
	int numChars = 0, i;
	char nextP[1], nextK[1];
	
	if (argc < 4) { fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); exit(0); } // Check usage & args
	char *plainTextFile = argv[1];
	char *keyFile = argv[2];
	
	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){ // Connect socket to address
		fprintf(stderr, "Error: could not contact opt_enc_d on port %d\n", portNumber);
		exit(2);
	}

	// Get plaintext from file, store in plaintext array
	memset(text, '\0', sizeof(text)); // Clear out the text array
	//open plain text file
	plainTextFD = open(plainTextFile, O_RDONLY);
	if(plainTextFD < 0)
		error("ERROR opening plaintext file\n");
	//read one character at a time from plaintext into array, checking for invalid characters
	while(read(plainTextFD, nextP, sizeof(char))){
		if(*nextP == '\n')//stop reading at newline char- anything after will be ignored
			break;
		text[numChars] = *nextP; //store character in array
		//validate characters: only valid chars have ascii values of 32 or in range 65-90
		if( !(text[numChars] == 32 || (text[numChars] >= 65 && text[numChars] <= 90)) ) //if invalid char
			error("ERROR: invalid characters in plaintext file\n");
		numChars++;
	}
	close(plainTextFD);	
	//add termination character '$' to text array
	strcat(text, "$");
	
	//get key from file, store in key array
	memset(key, '\0', sizeof(key));
	//open key file
	keyFD = open(keyFile, O_RDONLY);
	if(keyFD < 0)
		error("ERROR opening key file\n");
	for(i=0; i<numChars; i++){
		//error if key is too short
		if(!read(keyFD, nextK, sizeof(char)) || *nextK == '\n'){
			char msg[100];
			sprintf(msg, "Error: key '%s' is too short", keyFile);
			error(msg);
		}
		key[i] = *nextK;
		//validate characters
		if( !(key[i] == 32 || (key[i] >= 65 && key[i] <= 90)) ) //if invalid char
			error("ERROR: invalid characters in key file\n");
	}
	close(keyFD);
	//add termination character '$' to key array
	strcat(key, "$");
	
	//send identifier to server
	char id[4]; 
	strcpy(id, "ENC");
	charsWritten = send(socketFD, id, strlen(id), 0); // Write identifier to the server
	if (charsWritten < 0) fprintf(stderr, "CLIENT: ERROR writing text to socket\n");
	if (charsWritten < strlen(id)) fprintf(stderr, "CLIENT: WARNING: Not all text data written to socket!\n");
	
	// Get return message validating connection from server
	memset(id, '\0', sizeof(id)); // Clear out id again for reuse
	charsRead = recv(socketFD, id, sizeof(id) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) fprintf(stderr, "CLIENT: ERROR reading from socket\n");
	if(!strcmp(id, "OK")){
		//client has validated connection to server, continue normally
	}
	else if(!strcmp(id, "NO")){
		fprintf(stderr, "CLIENT: server has rejected connection\n");
		return 0;
	}
	else{
		fprintf(stderr, "CLIENT: server response not recognized. Terminating\n");
		exit(1);
	}
	
	// Send message to server in 999 byte chunks
	int len = strlen(text);
	int total = 0;
	while(total<len){
		charsWritten = send(socketFD, text+total, 999, 0); // Write to the server
		if (charsWritten < 0) fprintf(stderr, "CLIENT: ERROR writing text to socket\n");
		total += charsWritten;
	}
	if (total < len) fprintf(stderr, "CLIENT: WARNING: Not all text data written to socket\n");
	
	// Send key to server in 999 byte chunks
	len = strlen(key);
	total = 0;
	while(total<len){
		charsWritten = send(socketFD, key+total, 999, 0); // Write to the server
		if (charsWritten < 0) fprintf(stderr, "CLIENT: ERROR writing key to socket\n");
		total += charsWritten;
	}
	if (total < len) fprintf(stderr, "CLIENT: WARNING: Not all text data written to socket\n");

	//get ciphertext from server, read until termination character '$' found
	memset(text, '\0', sizeof(text));
	char buffer[1000];
	charsRead = 0;
	int n;
	while(!strstr(text, "$")){
		memset(buffer, '\0', sizeof(buffer));
		n = recv(socketFD, buffer, sizeof(buffer)-1, 0);
		if (n < 0) 
			fprintf(stderr, "ERROR reading from socket\n");
		strcat(text, buffer);
		usleep(2000);
	}

	//remove termination character
	text[strlen(text)-1] = '\0';
	printf("%s\n", text);	
	

	close(socketFD); // Close the socket
	return 0;
}

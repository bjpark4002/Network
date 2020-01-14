#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define SERVER_PORT 5432
#define MAX_LINE 80

int main(int argc, char * argv[])
{
    FILE *fp;
    struct hostent *hp;
    struct sockaddr_in sin;
    char *host;
    char *fname;
    char buf[MAX_LINE];
    int s;
    int slen;

    char buf_sending[MAX_LINE];
    char buf_recv[MAX_LINE];
    char indexCount = 1;
    int ack;
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1000;

    if (argc==3) {
        host = argv[1];
        fname= argv[2];
    }
    else {
        fprintf(stderr, "Usage: ./client_udp host filename\n");
        exit(1);
    }
    /* translate host name into peer’s IP address */
    hp = gethostbyname(host);
    if (!hp) {
        fprintf(stderr, "Unknown host: %s\n", host);
        exit(1);
    }

    fp = fopen(fname, "r");
    if (fp==NULL){
        fprintf(stderr, "Can't open file: %s\n", fname);
        exit(1);
    }

    /* build address data structure */
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
    sin.sin_port = htons(SERVER_PORT);

    /* active open */
    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket");
        exit(1);
    }

    socklen_t sock_len= sizeof sin;
    
    /* set socket open time */
    if (setsockopt(s,SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        perror("PError");
    }
    
    /* main loop: get and send lines of text */
    while(fgets(buf, 80, fp) != NULL){                 // get the line of file.
        slen = strlen(buf);
        buf[slen] ='\0';                            // put termination 
	    memset(buf_sending, 0, sizeof buf_sending); // initialize with 0.
	    buf_sending[0] = indexCount;                // this indicates index of line to track
	    strcat(buf_sending, buf);       
	    ack = 0;

	    while(ack == 0)
	    {
            memset(buf_recv, 0, sizeof buf_recv);   
            if(sendto(s, buf_sending, strlen(buf_sending), 0, (struct sockaddr *)&sin, sock_len)<0){
                perror("SendTo Error\n");
                exit(1);
            }
            recvfrom(s, buf_recv, sizeof(buf_recv), 0, (struct sockaddr *)&sin, &sock_len);
            if(buf_recv[0] == indexCount)   // right message was recieved. mark ack.
                ack = 1;    
        }
        
	    indexCount++;
        }
        *buf = 0x02;    
            if(sendto(s, buf, 1, 0, (struct sockaddr *)&sin, sock_len)<0){
            perror("SendTo Error\n");
            exit(1);
        }
        fclose(fp);
}


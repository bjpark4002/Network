#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>

#define SERVER_PORT 5432
#define MAX_LINE 256

int main(int argc, char * argv[])
{
    char *fname;
    char buf[MAX_LINE];
    struct sockaddr_in sin;
    int len;
    int s, i;
    struct timeval tv;
    char seq_num = 1; 
    FILE *fp;

    char birdFile[MAX_LINE][MAX_LINE];
    char buf_recv[MAX_LINE];
    char buf_send[MAX_LINE];
    int indexCount;

    if (argc==2) {
        fname = argv[1];
    }
    else {
        fprintf(stderr, "usage: ./server_udp filename\n");
        exit(1);
    }


    /* build address data structure */
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(SERVER_PORT);

    /* setup passive open */
    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("simplex-talk: socket");
        exit(1);
    }
    if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
        perror("simplex-talk: bind");
        exit(1);
    }

    socklen_t sock_len = sizeof sin;

    fp = fopen(fname, "w");
    if (fp==NULL){
        printf("Can't open file\n");
        exit(1);
    }
    
    while(1){
        memset(buf_recv, 0, sizeof buf_recv);
        len = recvfrom(s, buf_recv, sizeof(buf_recv), 0, (struct sockaddr *)&sin, &sock_len);
        indexCount = buf_recv[0];

        if(len == -1){
            perror("PError");
        }    
        else if(len == 1){
            if (buf_recv[0] == 0x02){
                printf("Transmission Complete\n");
                break;
            }
            else{
                perror("Error: Short packet\n");
            }
        }
	    
        else if(len > 1){
        	strcpy(birdFile[indexCount], buf_recv+1);
        }
        
        memset(buf_send, 0, sizeof buf_send);
        buf_send[0] = indexCount;
        if(sendto(s, buf_send, strlen(buf_send), 0, (struct sockaddr *)&sin, sock_len)<0){
            perror("SendTo Error\n");
            exit(1);
        }

    }
    i = 1;
    for(i; strlen(birdFile[i]) != 0; i++)
    {
            if(fputs((char *) birdFile[i], fp) < 1){
                printf("fputs() error\n");
            }
    }
    fclose(fp);
    close(s);
}

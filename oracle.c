#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <openssl/des.h>
#include <openssl/rand.h>

#define BLOCK 8
#define BUFSIZE 64
#define NAMELEN 256

void revuchararr(unsigned char a[8]){
	if(a != NULL){
		int low = 0;
		int high = 7;
		while(low < high){
			unsigned char temp = a[low];
			a[low] = a[high];
			a[high] = temp;
			low++;
			high--;
		}
	}
}

void num2uchararray(long unsigned int v, unsigned char a[8]){
	int x = v;
	int it = 0;
	while(x>0 && it<8){
		int temp = x%256;
		a[it] = temp;
		x /= 256;
		it++;
	}
	revuchararr(a);
}

//putting any value after the first 2 arguments will fix the key at 2^factor
int main(int argc, char *argv[]){ 
	if(argc == 4) //trapping for the special case of a fixed key value
	{}else if(argc != 3){
		printf("Usage:%s <input_file> <key_factor>\n",argv[0]);
		return 1;
	}

	char outname[NAMELEN];
	unsigned char in[BUFSIZE], out[BUFSIZE], back[BUFSIZE];
	DES_cblock key; //the cblock key
	DES_key_schedule keysched; //for key scheduling

	memset(in, 0, sizeof(in)); //zero the buffers
	memset(out, 0, sizeof(out));
	memset(back, 0, sizeof(back));
 
	srand(time(NULL)); //seed the rand() randomizer using time
	long int seeder = rand();
	long unsigned int factor = atoi(argv[2]); //factor to use 2^key_factor
	srand48(seeder); //seed the randomizer
	long unsigned int value = lrand48()%(1l<<factor);

	if(argc == 4){ //if an extra argument, then fix the key at 2^factor
		value = 1l<<factor; //fix at the factor value
	}

	unsigned char randkey[8];
	memset(randkey,0,sizeof(*randkey)*8);
	printf("Random Key Value = %lu\n",value);
	num2uchararray(value,randkey);
	int i;
	for(i=0;i<8;i++){ //copy the number into the key.
		key[i] = randkey[i];
	}
	DES_set_odd_parity(&key);
	printf("randkey|key(with odd parity set, so it may differ)\n");
	for(i=0;i<8;i++){
		printf("%03u|%03u\n",randkey[i],key[i]);
	}
	printf("\n");

	DES_set_key((C_Block *)key, &keysched); //expand the key for speed

	//encrypt the actual file to an output file
	strcpy(outname,argv[1]); //setup output file name
	strncat(outname,"_output",8); //add a suffix to the file

	int rfd,wfd; //read and write file descriptors
	if((rfd = open(argv[1],O_RDONLY)) == -1){
		perror("open error for input file\n");
	}
	if((wfd = open(outname,O_WRONLY|O_CREAT,
		S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH)) == -1){
		perror("open error for output file\n");
	}

	int r = -1;
	while(r != 0){
		r = read(rfd,in,BLOCK); //read in 8 bytes
		if(r == -1){
			printf("error:%s\n",strerror(errno));
		}else{
			if(r != 0){ //encrypt block
				DES_ecb_encrypt((C_Block *)in,(C_Block *)out, &keysched, DES_ENCRYPT);
				write(wfd,out,BLOCK); //write to outputfile
			}
		}
	}

	close(rfd); //close the files
	close(wfd);

	return 0;
}

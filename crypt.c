#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void encrypt();
void decrypt();
void grabKey();

void f();
void g();
unsigned char k();

typedef unsigned long long int Key;

Key key;

int main(int argc, char **argv)
{
	// Plaintext file: plaintext.txt (regular text)
	// Key file: key.txt (16 chars of HEX)
	// Output file: out.txt (entirely HEX, indefinite size)

	printf("Size of unsigned long long int: %ld\n", sizeof(unsigned long long int));

	if(argc == 2)
	{
		if(strcmp(argv[1], "encrypt") == 0)
		{
			grabKey();
			encrypt();			
		}
		else if(strcmp(argv[1], "decrypt") == 0)
		{
			grabKey();
			decrypt();
		}
		else
			fprintf(stderr, "Error: invalid arguments to crypt\nUsage:\n\t$ crypt <encrypt/decrypt>\n");
	}
	else
	{
		fprintf(stderr, "Error: invalid number of arguments to crypt\nUsage:\n\t$ crypt <encrypt/decrypt>\n");
	}
	
}

void encrypt()
{
	int plaintext_file_fd = open("plaintext.txt", O_RDONLY);

	if(plaintext_file_fd < 0)
	{
		fprintf(stderr, "Error: unable to open plaintext file for reading.\n%s\n", strerror(errno));
		exit(1);
	}

	unsigned char block[8];
	ssize_t actualLen;

	// while we're able to grab stuff from the file...
	while((actualLen = read(plaintext_file_fd, block, 8)) > 1)
	{
		if(actualLen != 8)
		{
			// do some padding
			for(int i = actualLen; i < 8; i++)
			{
				block[i] = 0;
			}
		}

		//TODO write this part after writing f,g, and k

	}
}

void decrypt()
{

}

void grabKey()
{
	int key_fd = open("key.txt", O_RDONLY);

	if(key_fd < 0)
	{
		fprintf(stderr, "Error: unable to open key file for reading.\n%s\n", strerror(errno));
		exit(1);
	}

	char keyBuf[17], highPart[9], lowPart[9];

	memset(highPart, 0, strlen(highPart));
	memset(lowPart, 0, strlen(lowPart));

	int bytesRead = read(key_fd, keyBuf, 16);

	if(bytesRead != 16)
	{
		fprintf(stderr, "Error: key file is of invalid size (must be 16 bytes)\n");
		exit(1);
	}

	close(key_fd);

	strncat(highPart, keyBuf, 8);
	strncat(lowPart, &keyBuf[8], 8);

	// keyBuf now has 16 bytes of hex text. Now we need to convert that to an integer in base 10.

	key = (Key)strtoll(highPart, NULL, 16) << 32 | ((Key)strtoll(lowPart, NULL, 16) & 0xffffffff);
}
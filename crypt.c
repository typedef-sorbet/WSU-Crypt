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

void f();
void g();
void k();

int main(int argc, char **argv)
{
	// Plaintext file: plaintext.txt (regular text)
	// Key file: key.txt (16 chars of HEX)
	// Output file: out.txt (entirely HEX, indefinite size)

	if(argc == 2)
	{
		if(strcmp(argv[1], "encrypt") == 0)
			encrypt();
		else if(strcmp(argv[1], "decrypt") == 0)
			decrypt();
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
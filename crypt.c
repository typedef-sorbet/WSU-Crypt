#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

// TODO rename the ciphertext outfile to ciphertext.txt

#define LEFT true
#define RIGHT false

typedef unsigned long long int Key;
typedef unsigned long long int Cryptext;
typedef unsigned short Word;
typedef unsigned char Byte;

typedef struct fdata{
	Word f0;
	Word f1;
}FData;

void encrypt();
void decrypt();
void grabKey();
void rightRotateKey();
void leftRotateKey();
void printKey();
Byte nthKeyByte(int);
Word nthKeyWord(int);
Word *wordify(char[]);
Word *wordifyCipher(char[]);
Word rotateWord(Word, bool);

FData f(Word, Word, int, bool);
Word g(Word, int, Byte *);
unsigned char k(int, bool);

Key key;

Byte ftable[] = {0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
				0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
				0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
				0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
				0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
				0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
				0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
				0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
				0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
				0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
				0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
				0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
				0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
				0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
				0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
				0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46};

int main(int argc, char **argv)
{
	// Plaintext file: plaintext.txt (regular text)
	// Key file: key.txt (16 chars of HEX)
	// Output file: out.txt (entirely HEX, indefinite size)

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
	FILE *outstream = fopen("out.txt", "w+");

	if(plaintext_file_fd < 0)
	{
		fprintf(stderr, "Error: unable to open plaintext file for reading.\n%s\n", strerror(errno));
		exit(1);
	}

	if(outstream == NULL)
	{
		fprintf(stderr, "Error: unable to open outfile for writing. (Invalid permissions?)\n%s\n", strerror(errno));
		exit(1);
	}

	char block[8];
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

		// whitening stage
		Word *words = wordify(block);
		Word r[4];
		Word new_r[4];

		for(int i = 0; i < 4; i++)
		{
			r[i] = words[i] ^ nthKeyWord(3 - i);
		}

		//whitening done

		// encrypt for 16 rounds
		for(int round = 0; round < 16; round++)
		{
			FData data = f(r[0], r[1], round, false);
			new_r[0] = rotateWord(r[2] ^ data.f0, RIGHT);
			new_r[1] = rotateWord(r[3], LEFT) ^ data.f1;
			new_r[2] = r[0];
			new_r[3] = r[1];

			for(int i = 0; i < 4; i++) 
				r[i] = new_r[i];
		}

		Word y[4];

		y[0] = r[2];
		y[1] = r[3];
		y[2] = r[0];
		y[3] = r[1];

		// whitening stage part 2: electric boogaloo
		for(int i = 0; i < 4; i++)
		{
			y[i] ^= nthKeyWord(3 - i);
		}

		// output is concatenation of y[0:4]
		// I know, that's python syntax, but this is a comment, so sue me.

		Cryptext c = (Cryptext)((Cryptext)y[0] << (16*3) | (Cryptext)y[1] << (16*2) | (Cryptext)y[2] << 16 | (Cryptext)y[3]);

		fprintf(outstream, "%llx", c);

		//leave this at the end
		memset(block, 0, 8);
		free(words);
	}

	close(plaintext_file_fd);
	fclose(outstream);
}

void decrypt()
{
	int ciphertext_file_fd = open("out.txt", O_RDONLY);
	FILE *outstream = fopen("plaintextcopy.txt", "w+");

	if(ciphertext_file_fd < 0)
	{
		fprintf(stderr, "Error: unable to open ciphertext file for reading.\n%s\n", strerror(errno));
		exit(1);
	}

	if(outstream == NULL)
	{
		fprintf(stderr, "Error: unable to open outfile for writing. (Invalid permissions?)\n%s\n", strerror(errno));
		exit(1);
	}

	char block[16];
	ssize_t actualLen;

	// while we can still read from the file
	while((actualLen = read(ciphertext_file_fd, block, 16)) > 1)
	{
		if(actualLen != 16)
		{
			// this should never happen
			for(int i = actualLen; i < 16; i++)
				block[i] = 0;
		}

		// whitening stage
		Word *words = wordifyCipher(block);
		Word r[4];
		Word new_r[4];

		for(int i = 0; i < 4; i++)
		{
			r[i] = words[i] ^ nthKeyWord(3 - i);
		}

		//whitening done

		// encrypt for 16 rounds
		// count backwards for decryption
		for(int round = 15; round >= 0; round--)
		{
			FData data = f(r[0], r[1], round, true);
			new_r[0] = rotateWord(r[2], LEFT) ^ data.f0;
			new_r[1] = rotateWord(r[3] ^ data.f1, RIGHT);
			new_r[2] = r[0];
			new_r[3] = r[1];

			for(int i = 0; i < 4; i++) 
				r[i] = new_r[i];
		}

		Word y[4];

		y[0] = r[2];
		y[1] = r[3];
		y[2] = r[0];
		y[3] = r[1];

		// whitening stage part 2: electric boogaloo
		for(int i = 0; i < 4; i++)
		{
			y[i] ^= nthKeyWord(3 - i);
		}

		// y[0:4] contains 8 characters; two for each element

		// output
		for(int i = 0; i < 4; i++)
		{
			fprintf(outstream, "%c%c", (y[i] >> 8) & 0xff, y[i] & 0xff);
		}

		//leave this at the end
		memset(block, 0, 16);
		free(words);
	}

	close(ciphertext_file_fd);
	fclose(outstream);
}

Word rotateWord(Word word, bool isRotatingLeft)
{
	if(isRotatingLeft)
	{
		Word trimmings = (word >> 15) & 0x1;
		return word << 1 | trimmings;
	}
	else
	{
		Word trimmings = (word & 0x1) << 15;
		return word >> 1 | trimmings;
	}
}

Word *wordify(char block[])
{
	Word *wordArray = (Word *)malloc(4 * sizeof(Word));

	for(int i = 0; i < 8; i += 2)
	{
		wordArray[i/2] = (Word)((Word)block[i] << 8 | (Word)block[i+1]);
	}

	return wordArray;
}

Word *wordifyCipher(char block[])
{
	Word *wordArray = (Word *)malloc(4 * sizeof(Word));
	char palette[5];

	for(int i = 0; i < 16; i += 4)
	{
		memset(palette, 0, 5);
		strncat(palette, &block[i], 4);
		wordArray[i/4] = (Word)strtol(palette, NULL, 16);
	}

	return wordArray;
}

FData f(Word r0, Word r1, int round, bool isDecryption)
{
	Byte subkeys[12];

	int *additives = (!isDecryption)? (int[4]){0, 1, 2, 3} : (int[4]){3, 2, 1, 0};
	for(int i = 0; i < 12; i++)
	{
		subkeys[i] = k(4*round + additives[i%4], isDecryption);
	}

	if(isDecryption)
	{
		//reverse subkey order
		for(int i = 0; i < 6; i++)
		{
			Byte temp = subkeys[i];
			subkeys[i] = subkeys[11-i];
			subkeys[11-i] = temp; 
		}
	}

	Word t0 = g(r0, round, subkeys);
	Word t1 = g(r1, round, &subkeys[4]);

	FData data;
	Word concat1 = (Word)((Word)subkeys[8] << 8 | (Word)subkeys[9]);
	Word concat2 = (Word)((Word)subkeys[10] << 8 | (Word)subkeys[11]);

	data.f0 = (t0 + 2*t1 + concat1) % (1 << 16);
	data.f1 = (2*t0 + t1 + concat2) % (1 << 16);
	return data;
}

Word g(Word w, int round, Byte *keysToUse)
{
	Byte g1 = (Byte)((w >> 8) & 0xff);
	Byte g2 = (Byte)(w & 0xff);
	Byte g3 = ftable[g2 ^ keysToUse[0]] ^ g1;
	Byte g4 = ftable[g3 ^ keysToUse[1]] ^ g2;
	Byte g5 = ftable[g4 ^ keysToUse[2]] ^ g3;
	Byte g6 = ftable[g5 ^ keysToUse[3]] ^ g4;
	return (Word)((Word)g5 << 8 | (Word)g6);
}

unsigned char k(int x, bool isDecryption)
{
	if(isDecryption)
	{
		Byte xthByte = nthKeyByte(x);
		rightRotateKey();
		return xthByte;
	}
	else
	{
		leftRotateKey();
		return nthKeyByte(x);
	}
}

void rightRotateKey()
{
	// circular rotation, so make sure to save the front bit

	Key oldKey = key;
	Key trimmings = oldKey & 0x1;
	key = (trimmings << 63) | ((oldKey >> 1) & 0x7fffffffffffffff);
}

void leftRotateKey()
{
	// circular rotation, so make sure to save the end bit

	Key oldKey = key;
	Key trimmings = (oldKey >> 63) & 0x1;
	key = ((oldKey << 1) & 0xfffffffffffffffe) | (trimmings & 0x1);
}

Byte nthKeyByte(int n)
{
	n %= 8;
	return (Byte)((key >> (8 * n)) & 0xff);
}

Word nthKeyWord(int n)
{
	n %= 4;
	return (Word)((key >> (16 * n)) & 0xffff);
}

void printKey()
{
	// for debug use only!

	for(int i = 63; i >= 0; i--)
	{
		printf("%d", ((key >> i) & 0x1) == 1 ? 1 : 0);
	}
	printf("\n");
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
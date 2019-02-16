Author:		Spencer Warneke
Date:		February 15, 2019
Assignment:	Project 1
Class:		CS 427

Included files:
	Spencer_Warneke.zip
	├── crypt.c
	├── Makefile
	└── README.txt

To compile:
	$ make

To run:
	Ensure that a properly formatted key.txt exists in the same directory as the executable, as well as a plaintext.txt file, and run

		$ ./crypt encrypt

	This will write to the file cyphertext.txt, which can then be decrypted using

		$ ./crypt decrypt

	This will write to the file plaintextcopy.txt, in order to avoid overwriting the original file.
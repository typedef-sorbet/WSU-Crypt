CFLAGS = -Wall -pedantic -std=c99 -g

crypt: crypt.o
	gcc -o crypt crypt.o $(CFLAGS)
crypt.o: crypt.c
	gcc -c crypt.c $(CFLAGS)
clean:
	rm crypt crypt.o
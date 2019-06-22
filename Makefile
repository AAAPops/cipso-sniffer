### https://nullpointer.io/post/easily-embed-version-information-in-software-releases/
###
### export CC=gcc on x86


#CC = gcc
#CFLAGS = -Wall -std=c99 -D_XOPEN_SOURCE=600 -I../libs
CFLAGS = -Wall -l:libpcap.a
#CFLAGS = -l:libpcap.a
#LDFLAGS = -L../libs -lmytlpi

src = cipso-finder.c
#$(info  SRC == $(src))

VERSION = 0.1

#all: $(src)

raw_sock_capture: $(src)
	$(CC) -o cipso-finder  $(src)  $(CFLAGS) $(LDFLAGS) -DVERSION=\"$(VERSION)\"


.PHONY: clean 
clean:
	rm -f *.o  *.a  cipso-snoop cipso-finder

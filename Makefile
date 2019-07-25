### https://nullpointer.io/post/easily-embed-version-information-in-software-releases/
###

CC = gcc
CFLAGS = -Wall -Wno-unknown-pragmas -Wno-unused-variable
#CFLAGS = -Wall -std=c99 -D_XOPEN_SOURCE=600
#CFLAGS = -Wall -l:libpcap.a
#CFLAGS = -l:libpcap.a
#LDFLAGS = -L../libs -lmytlpi

src = main.c
#$(info  SRC == $(src))

VERSION = 0.3

#all: $(src)

cripper: $(src)
	$(CC) -o cripper  $(src)  $(CFLAGS) $(LDFLAGS) -DVERSION=\"$(VERSION)\"


.PHONY: clean 
clean:
	rm -f *.o  *.a  cipso-snoop cipso-finder

# makefile 
VERSION = 1.0.0
CC = gcc
TARGET = client
DEBUG = -Wall -c

BINPATH = ../../bin/

src = $(wildcard ./*.c) 
obj = $(patsubst ./%.c, ./%.o,$(src))

INC = -I../../include

LIBPATH = -L../../../libs/zeromq/lib/
LIBOBJ = -lzmq 
$(TARGET) : $(obj) 
	$(CC) $(obj) -o $(BINPATH)/$(TARGET) $(LIBPATH) $(LIBOBJ)
	@echo "\nmakefile compile version :$(VERSION), target :$(TARGET)\n"

%.o : %.c
	$(CC) $(DEBUG) $(INC) $^ -o $@ 
	

.PHONY :
clean :
	rm  $(obj)
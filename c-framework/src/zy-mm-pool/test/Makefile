TARGET  := zy-mm-test

CC      := gcc
LIBS    :=  -L. -L../src -lzy_mm -lrt
LDFLAGS :=
DEFINES :=
INCLUDE := -I. -I../src/
CFLAGS  := -g -Wall -O0 $(DEFINES) $(INCLUDE) $(LDFLAGS)
CXXFLAGS:= $(CFLAGS) -DHAVE_CONFIG_H
SHARE   := -o
#NEED_LIB_FILES    :=  $(wildcard ../lib/common.pb* ../lib/policy.pb-*)
#i think you should do anything here

#source file
SOURCE  := $(wildcard *.c) $(wildcard *.cpp)
OBJS    := $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCE)))

.PHONY : everything objs clean veryclean rebuild install prepare

everything : $(TARGET)

prepare :
	@echo "NEED_LIB_FILES: "$(NEED_LIB_FILES)
	@echo "not NEED_LIB_FILES: "$(notdir $(NEED_LIB_FILES))
	#$(foreach file, $(NEED_LIB_FILES), $(shell cp -f $(file) $(notdir $(file))))
all : $(TARGET)

objs : $(OBJS)

rebuild: veryclean everything

#install:
#	mkdir /apisec/lib/ -p
#	cp $(TARGET) /apisec/lib/ -f

clean :
	rm -fr *.o
	rm -fr $(TARGET)
	#rm -fr $(notdir $(NEED_LIB_FILES))

$(TARGET) : $(OBJS)
		$(CC) $(CXXFLAGS) $(SHARE) $@ $(OBJS) $(LDFLAGS) $(LIBS)

NAME                  := sigtool
VERSION               := 1.0.0
PROFILE               ?= default
ARCH                  ?= $(shell uname -m | sed 's/i.86/x86/;s/x86_64/x64/;s/arm.*/arm/;s/mips.*/mips/')
CC_ARCH               ?= $(shell echo $(ARCH) | sed 's/x86/i686/;s/x64/x86_64/')
OS                    ?= linux
CC                     = g++
CONFIG                ?= $(OS)-$(ARCH)-$(PROFILE)
BUILD                 ?= $(shell pwd)
LBIN                  ?= $(BUILD)/bin
PATH                  := $(LBIN):$(PATH)

ME_COM_COMPILER       ?= 1
OPENSSL_LIB_PATH      ?= /home/yangweiming/ProgramFiles/lib/
OPENSSL_INCLUDE_PATH  ?= /home/yangweiming/ProgramFiles/include/


CFLAGS                += -fPIC  -Wall
IFLAGS                += -I./inc -I$(OPENSSL_INCLUDE_PATH)
LIBPATHS              += -L$(OPENSSL_LIB_PATH)
LIBS                  +=  -lcrypto -ldl

DEBUG                 ?= debug
CFLAGS-debug          ?= -g
DFLAGS-debug          ?= -DME_DEBUG
LDFLAGS-debug         ?= -g
DFLAGS-release        ?= 
CFLAGS-release        ?= -O2
LDFLAGS-release       ?= 
CFLAGS                += $(CFLAGS-$(DEBUG))
DFLAGS                += $(DFLAGS-$(DEBUG))
LDFLAGS               += $(LDFLAGS-$(DEBUG)) 

TARGETS += $(BUILD)/obj/key.o
TARGETS += $(BUILD)/obj/pkcs1_rsa.o
TARGETS += $(BUILD)/out/libgo.so
TARGETS += $(BUILD)/out/$(NAME)

ifndef SHOW
.SILENT:
endif

all build compile: prep $(TARGETS) compiler 

.PHONY: prep clean help compiler

prep:
	@echo "      [Info] Use "make SHOW=1" to trace executed commands."
	@[ ! -x $(BUILD)/out ] && mkdir -p $(BUILD)/out; true
	@[ ! -x $(BUILD)/obj ] && mkdir -p $(BUILD)/obj; true
	

clean:
	@echo "    [clean] delete $(BUILD)/obj/*.o"
	@echo "    [clean] delete $(BUILD)/out/$(NAME)"
	rm -f $(BUILD)/obj/key.o
	rm -f $(BUILD)/obj/pkcs1_rsa.o
	rm -f $(BUILD)/obj/main.o
	rm -f $(BUILD)/out/sigtool

#
#   Key.o
#
DEPS_1 += inc/key.h
$(BUILD)/obj/key.o: \
    src/key.cpp $(DEPS_1)
	@echo '   [Compile] $(BUILD)/obj/key.o'
	$(CC) -c -o $(BUILD)/obj/key.o $(CFLAGS) $(DFLAGS) -D_FILE_OFFSET_BITS=64   $(IFLAGS) src/key.cpp

#
#   pkcs1_rsa.o
#
DEPS_2 += inc/key.h
DEPS_2 += inc/pkcs1_rsa.h

$(BUILD)/obj/pkcs1_rsa.o: \
    src/pkcs1_rsa.cpp $(DEPS_2)
	@echo '   [Compile] $(BUILD)/obj/pkcs1_rsa.o'
	$(CC) -c -o $(BUILD)/obj/pkcs1_rsa.o $(CFLAGS) $(DFLAGS) -D_FILE_OFFSET_BITS=64   $(IFLAGS) src/pkcs1_rsa.cpp
	
#
#   main.o
#
DEPS_3 += inc/osdep.h
DEPS_3 += inc/pkcs1_rsa.h

$(BUILD)/obj/main.o: \
    src/main.cpp $(DEPS_3)
	@echo '   [Compile] $(BUILD)/obj/main.o'
	$(CC) -c -o $(BUILD)/obj/main.o $(CFLAGS) $(DFLAGS) -D_FILE_OFFSET_BITS=64   $(IFLAGS) src/main.cpp
	

#
#   libgo
#
DEPS_4 += inc/key.h
DEPS_4 += inc/pkcs1_rsa.h
DEPS_4 += $(BUILD)/obj/key.o
DEPS_4 += $(BUILD)/obj/pkcs1_rsa.o

$(BUILD)/out/libgo.so: $(DEPS_4)
	@echo '      [Link] $(BUILD)/out/libgo.so'
	$(CC) -shared -o $(BUILD)/out/libgo.so $(LDFLAGS) $(LIBPATHS) "$(BUILD)/obj/key.o" "$(BUILD)/obj/pkcs1_rsa.o"   
	
#
#   sigtool
#
DEPS_5 += inc/osdep.h
DEPS_5 += inc/key.h
DEPS_5 += inc/pkcs1_rsa.h
DEPS_5 += $(BUILD)/obj/main.o

LIBS_5 += -lgo
LIBPATHS_5 += -L./out
$(BUILD)/out/sigtool: $(DEPS_5)
	@echo '      [Link] $(BUILD)/out/sigtool'
	$(CC) -o $(BUILD)/out/sigtool $(LDFLAGS)  "$(BUILD)/obj/main.o"  "$(BUILD)/obj/key.o" "$(BUILD)/obj/pkcs1_rsa.o"   $(LIBPATHS) $(LIBS)
	
help:
	@echo '' >&2
	@echo 'usage: make [compile, clean]' >&2
	@echo '' >&2
	@echo '  OPENSSL_LIB_PATH                    # The OpenSSL LIB PATH' >&2
	@echo '  OPENSSL_INCLUDE_PATH                # The OpenSSL INCLUDE PATH' >&2
	@echo '' >&2
	@echo '  ARCH               # CPU architecture (x86, x64, ppc, ...)' >&2
	@echo '  OS                 # Operating system (linux, macosx, windows, vxworks, ...)' >&2
	@echo '  CC                 # Compiler to use ' >&2
	@echo '  LD                 # Linker to use' >&2
	@echo '  CFLAGS             # Add compiler options. For example: -Wall' >&2
	@echo '  DEBUG              # Set to "debug" for symbols, "release" for optimized builds' >&2
	@echo '  DFLAGS             # Add compiler defines. For example: -DCOLOR=blue' >&2
	@echo '  IFLAGS             # Add compiler include directories. For example: -I/extra/includes' >&2
	@echo '  LDFLAGS            # Add linker options' >&2
	@echo '  LIBPATHS           # Add linker library search directories. For example: -L/libraries' >&2
	@echo '  LIBS               # Add linker libraries. For example: -lpthreads' >&2
	@echo '' >&2
	@echo 'Use "SHOW=1 make" to show executed commands.' >&2
	@echo '' >&2
	

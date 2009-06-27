# TSDEC
# Makefile for native mingw32 under win32

#
# Compiler command definitions
#
CC          = gcc
LD          = gcc
RM          = rm

# use these flags for release
CFLAGS      = -Wall -W -Wno-unused -O3
CPPFLAGS    = #-DWIN32_VERSION -I.
#LDFLAGS     = -liberty

# use these flags for debugging 
#CFLAGS      = -Wall -W -Wno-format -Wno-unused -g
#CPPFLAGS    = -DWIN32_VERSION -I. -DECHO_FUNCTION_CALL
#LDFLAGS     = -g -liberty

objdir      = obj
dvbcsadir   = dvbcsa
              
#
# Pattern rules to make the .o files end up in directory o
#
$(objdir)/%.o : %.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $(objdir)/$*.o $*.c
$(objdir)/%.o : $(dvbcsadir)/%.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $(objdir)/$*.o $(dvbcsadir)/$*.c

#
# 
#


TARGET1 = tsdec.exe
OBJS1 =  $(objdir)/csa.o                    \
         $(objdir)/tsdec.o                  \
         $(objdir)/dvbcsa_algo.o            \
         $(objdir)/dvbcsa_block.o           \
         $(objdir)/dvbcsa_bs_algo.o         \
         $(objdir)/dvbcsa_bs_block.o        \
         $(objdir)/dvbcsa_bs_key.o          \
         $(objdir)/dvbcsa_bs_stream.o       \
         $(objdir)/dvbcsa_bs_transpose.o    \
         $(objdir)/dvbcsa_bs_transpose32.o  \
         $(objdir)/dvbcsa_stream.o          

## fixa!
HEADERS = csa.h csa_testcases.h      \
   dvbcsa\config.h dvbcsa\dvbcsa.h dvbcsa\dvbcsa_bs.h dvbcsa\dvbcsa_bs_altivec.h \
   dvbcsa\dvbcsa_bs_mmx.h dvbcsa\dvbcsa_bs_sse.h dvbcsa\dvbcsa_bs_uint32.h \
   dvbcsa\dvbcsa_bs_uint64.h dvbcsa\dvbcsa_pv.h
	
#
# Build EXE
#
$(TARGET1): $(OBJS1) makefile
	$(LD) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

#
# Rules for the object files
#

$(objdir)/csa.o:                        csa.c											$(HEADERS)
$(objdir)/tsdec.o:                      tsdec.c											$(HEADERS)
$(objdir)/dvbcsa_algo.o:                $(dvbcsadir)/dvbcsa_algo.c				$(HEADERS)
$(objdir)/dvbcsa_block.o:               $(dvbcsadir)/dvbcsa_block.c				$(HEADERS)
$(objdir)/dvbcsa_bs_algo.o:             $(dvbcsadir)/dvbcsa_bs_algo.c			$(HEADERS)
$(objdir)/dvbcsa_bs_block.o:            $(dvbcsadir)/dvbcsa_bs_block.c         $(HEADERS)
$(objdir)/dvbcsa_bs_key.o:              $(dvbcsadir)/dvbcsa_bs_key.c           $(HEADERS)
$(objdir)/dvbcsa_bs_stream.o:           $(dvbcsadir)/dvbcsa_bs_stream.c        $(HEADERS)
$(objdir)/dvbcsa_bs_transpose.o:        $(dvbcsadir)/dvbcsa_bs_transpose.c     $(HEADERS)
$(objdir)/dvbcsa_bs_transpose128.o:     $(dvbcsadir)/dvbcsa_bs_transpose128.c  $(HEADERS)
$(objdir)/dvbcsa_bs_transpose32.o:      $(dvbcsadir)/dvbcsa_bs_transpose32.c   $(HEADERS)
$(objdir)/dvbcsa_bs_transpose64.o:      $(dvbcsadir)/dvbcsa_bs_transpose64.c   $(HEADERS)
$(objdir)/dvbcsa_stream.o:              $(dvbcsadir)/dvbcsa_stream.c           $(HEADERS)

#
# Remove EXE and object files and backup files
#
clean:
	$(RM) $(TARGET1) $(objdir)/*.o

all:	$(TARGET1)

#install: $(TARGET1)
#	cp $(TARGET1) ../bin
#	strip ../bin/$(TARGET1)


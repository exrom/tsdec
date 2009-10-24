# TSDEC Makefile for MinGW 5.1.4

CC          = gcc
LD          = gcc
RM          = rm

CFLAGS      = -Wall -W -O3

obj/%.o : %.c
	$(CC) -c $(CFLAGS) -o obj/$*.o $*.c
obj/%.o : dvbcsa/%.c
	$(CC) -c $(CFLAGS) -o obj/$*.o dvbcsa/$*.c

objgui/%.o : %.c
	$(CC) -D _WINDOWS -c $(CFLAGS) -o objgui/$*.o $*.c
objgui/%.o : dvbcsa/%.c
	$(CC) -D _WINDOWS -c $(CFLAGS) -o objgui/$*.o dvbcsa/$*.c


TARGETCL		= ../tsdec
TARGETGUI	= ../tsdec_gui
TARGETS =  $(TARGETCL) $(TARGETGUI)
OBJSCL  =  obj/csa.o                    \
           obj/tsdec.o                  \
           obj/dvbcsa_algo.o            \
           obj/dvbcsa_block.o           \
           obj/dvbcsa_bs_algo.o         \
           obj/dvbcsa_bs_block.o        \
           obj/dvbcsa_bs_key.o          \
           obj/dvbcsa_bs_stream.o       \
           obj/dvbcsa_bs_transpose.o    \
           obj/dvbcsa_bs_transpose32.o  \
           obj/dvbcsa_stream.o          

OBJSGUI =  objgui/csa.o                    \
           objgui/tsdec.o                  \
           objgui/dvbcsa_algo.o            \
           objgui/dvbcsa_block.o           \
           objgui/dvbcsa_bs_algo.o         \
           objgui/dvbcsa_bs_block.o        \
           objgui/dvbcsa_bs_key.o          \
           objgui/dvbcsa_bs_stream.o       \
           objgui/dvbcsa_bs_transpose.o    \
           objgui/dvbcsa_bs_transpose32.o  \
           objgui/dvbcsa_stream.o          \
           objgui/tsdecgui.o               \
           objgui/icon.o


all:	$(TARGETS)

objgui/icon.o : rc.rc
	windres rc.rc objgui/icon.o
         
HEADERS = csa.h csa_testcases.h      \
   dvbcsa\config.h dvbcsa\dvbcsa.h dvbcsa\dvbcsa_bs.h dvbcsa\dvbcsa_bs_altivec.h \
   dvbcsa\dvbcsa_bs_mmx.h dvbcsa\dvbcsa_bs_sse.h dvbcsa\dvbcsa_bs_uint32.h \
   dvbcsa\dvbcsa_bs_uint64.h dvbcsa\dvbcsa_pv.h
	
# Build command line excecutable
$(TARGETCL): $(OBJSCL) 
	$(LD) -o $(TARGETCL) $(OBJSCL)
cl: $(TARGETCL)

# Build grahpical excecutable
$(TARGETGUI): $(OBJSGUI) 
	$(LD) -mwindows -o $(TARGETGUI) $(OBJSGUI)
gui: $(TARGETGUI)


clean:
#	$(RM) $(TARGETCL) $(TARGETGUI) $(objdir)/*.o
	$(RM) $(TARGETCL).exe $(TARGETGUI).exe obj/*.o objgui/*.o


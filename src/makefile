# TSDEC makefile for gcc

.PHONY : all clean

CC          = gcc
LD          = gcc

CFLAGS      = -Wall -W -O3

obj/%.o : %.c
	$(CC) -c $(CFLAGS) -o obj/$*.o $*.c
obj/%.o : dvbcsa/%.c
	$(CC) -c $(CFLAGS) -o obj/$*.o dvbcsa/$*.c

objgui/%.o : %.c
	$(CC) -D _WINDOWS -c $(CFLAGS) -o objgui/$*.o $*.c
objgui/%.o : dvbcsa/%.c
	$(CC) -D _WINDOWS -c $(CFLAGS) -o objgui/$*.o dvbcsa/$*.c

TSDEC     = ../tsdec
TSDECGUI  = ../tsdec_gui
OBJS    =  obj/csa.o                    \
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

all: $(TSDEC)

# Build command line excecutable
$(TSDEC): $(OBJS)
	$(LD) -o $(TSDEC) $(OBJS)

# Build grahpical executable for win32
$(TSDECGUI): $(OBJSGUI) 
	$(LD) -mwindows -o $(TSDECGUI) $(OBJSGUI)
gui: $(TSDECGUI)

objgui/icon.o : rc.rc
	windres rc.rc objgui/icon.o
         
clean:
	rm -f $(TSDEC) obj/*.o $(TSDECGUI) objgui/*.o


# TSDEC makefile for gcc

.PHONY : all clean

CC          = gcc
LD          = gcc

CFLAGS      = -Wall -W -O3

obj/%.o : src/%.c
	mkdir -p obj && $(CC) -c $(CFLAGS) -o obj/$*.o src/$*.c
obj/%.o : src/dvbcsa/%.c
	mkdir -p obj && $(CC) -c $(CFLAGS) -o obj/$*.o src/dvbcsa/$*.c

objgui/%.o : src/%.c
	mkdir -p objgui && $(CC) -D _WINDOWS -c $(CFLAGS) -o objgui/$*.o src/$*.c
objgui/%.o : src/dvbcsa/%.c
	mkdir -p objgui && $(CC) -D _WINDOWS -c $(CFLAGS) -o objgui/$*.o src/dvbcsa/$*.c

TSDEC     = tsdec
TSDECGUI  = tsdec_gui
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

objgui/icon.o : src/rc.rc
	windres src/rc.rc objgui/icon.o
         
clean:
	rm -rf $(TSDEC) $(TSDECGUI) obj objgui


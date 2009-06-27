######################################################
TSDEC - the transport stream offline decrypter
######################################################


Now what is TSDEC?
-------------------
It is a small command line program that decrypts recorded DVB transport stream 
files (*.ts) with the recorded control words from a CWL file using the common 
scrambling algorithm.


The idea:
---------
Remember "VCL" files from Videocrypt times? This is its successor for DVB.

One party with a valid subscription card records the decrypted control words
to a cw log file, and makes them available later.
People without subscription record the encrypted video/audio streams, and
decode them later using the information found in the .cwl file.

This works for all DVB crypt systems (viaccess, seca, biss, nagra,...) because 
the system defines only what happens inside the smartcard. The smartcard sends 
the control word to the CAM and what the CAM does with it to decrypt the 
transport stream is always the same and independent from the crypt system used.


Why offline decryption?
------------------------
Today, control words can be shared 'online' via cardsharing. Anonymous sharing 
is not possible with this approach as the IP adress must be known by the sharing 
partners. With offline decryption the CWL files may be uploaded and shared 
anonymously. 
Offline decryption also has no problems with network latency. There will be 
no picture freezes or things like that because of CWs arriving too late.
Control words can be logged by cardservers, proxies or card clients.

Is it illegal? I'm afraid it might be in most European countries.
Perhaps it isn't, because - of course - it is released for educational purposes
only. 


How to use:
------------------
1. Record a TS file from an encrypted channel and make sure the CWs are logged 
by someone else at the same time. For testing purposes you may record the CWs 
yourself on another device. Recording works best with budget DVB cards. With FF 
cards or set top boxes you may not get a clean stream (explanation see below). 
DVBdream is a good program for recording. In the CWlogging directory are some 
scripts to log cws on the client side.

2. start TSDEC on the dos command prompt like this:
TSDEC -f logfile.CWL -i recording.ts -o recording_decrypted.ts

TSDEC will now try to sync, meaning trying to find TS packets matching to a 
cw. If the recorded ts file was ok and you have the CWs from the correct 
program and time, you see "sync at packet..." and tsdec should write the 
decrypted file recording_decrypted.ts on your disk. 
TSDEC will tell you if the transport stream is corrupt or the CWL is not well 
formated. 
You may test decryption process with the example cwl and ts files.

3. Watch recording_decrypted.ts with a media player which supports ts. Vlc is a 
good choice.


How does TSDEC work?
---------------------
When decrypting with a cwl file, tsdec first reads all cws into memory and 
checks for alternating parity. It also checks for correct checksum at byte 4 
and 8 and corrects it if necessary. 
Then it reads the input ts file packet after packet (and checks for correct 
format). If the packet has the PUSI flag set to one, this indicates the start of 
an mpeg frame. Every mpeg frame starts with a special header. This header cannot 
be seen of course until the packet is decrypted correctly. Tsdec tries to decrypt
this pusi packet with all available CWs. If the mpeg header is found with a 
certain cw, then the TS and the CWs are in sync. After that, every encrypted 
packet will be decrypted with the same cw until the parity changes. On parity 
change, the next cw from the cwl is used.
When the parity changes e.g. from 0 to 1 the parity might toggle for some time 
until it changes finally to 1. This is an audio/video muxing problem on some 
transmissions. The stream might look like this:
VVVVVAVVVVVVAVVVVVVAVVVVVVAVVVVVVAVVVVVVAVVVVVVAVVVVVVAVVVVVVV
00000000000010000001000000100000010000111111111111111111111111
The cw change blocker (-b) supresses the usage of a new cw from the CWL for each 
parity if it happens after less than n packets. The value must be decreased if 
the bit rate of the stream is very low (1000 packets per second for a ~1.4 MBit 
stream) and if the CW changes very often. Use greater value if parity toggles 
for a longer time and tsdec accidently uses the next cw from cwl file. 
Default: 300
If another pusi packet comes along while synced, the correct decryption is 
checked again. If the decryption fails (ts corrupt, missing or wrong CWs in cwl) 
the packet is tried to be decrypted with all other cws again (resync). 
Unfortunately there will be a short freeze in the decrypted video then.

Tsdec can encrypt and decrypt streams with a constant cw. Decryption can be used 
to decrypt certain crypt systems like biss. 
Encryption with constant CW may be used for recordings from full featured DVB
cards or set top boxes. Such devices with hardware based CSA decryption maybe
unable to record an encrypted TS without decrypting it (e.g. the dBox 2). 
Unfortunately if no correct control word is available at that time, the stream 
is "decrypted" with the wrong CW. If you know this wrong CW, you can reverse the 
wrong decryption by re-encrypting the stream and then decrypt it with the CWs 
from CWL.

A ts file will usually contain some unencrypted packets like PMT, PAT, Text, EPG.
Tsdec does not care about these packets and simply writes them directly to the 
outfile. The PAT/PMT is necessary for most players to assign the streams.

Use the analyze (-a) option to get a quick overview over the PIDs found in the 
TS file . Tsdec will print a PID statistics and will not decrypt.

For debugging purposes you may want to raise the verbose level type -v 9. The 
messages go to stderr not stdout. To log them into a file write 2>log.txt.

The CWL file format
---------------------
Each line of the file contains either the even or the odd part of one cw.
0 00 00 00 00 00 00 00 00  # 12:00:00
1 11 22 33 66 44 55 66 FF  # 12:00:10
0 77 88 99 98 AA BB CC 31  # 12:00:20
1 FF FF FF FD FF FF FF FD  # 12:00:30
Its important to always have an alternating parity sequence, otherwise tsdec 
looses sync. If you write a cw logger, take care about the first cw change. You
can not select the correct parity part of the first cw until you know which part
changes next.
Everything after # is comment. The time of the cw change is in the comment behind 
the line. The time should be written there to make merging of dirrerent CWL files 
easier.

I'd recommend this convention for .cwl file names:
  090619-S192o-F11758h-C1702-I000A-P000000-DISCOVERY_CHANNEL.cwl
Every useful and available information about the logged channel should be in the 
file name and have the defined code letter in front:
S  satellite position, F  frequency, C  CAID, I  service-ID, P  provider-ID.
The program name is the last part for better human readability (must not contain 
'-', spaces or special characters).
More infos (e.g. timezone, logging software,..) can be written into a comment
line in the top of the cwl.

  
Limitations, things to be done:
--------------------------------
- usage of the csa bitslice implementation (FFdecsa) of LIBDVBCSA for speed up.
- fool-proof GUI. Error codes are exported already.
- on the fly encryption (constant CW) -> decryption (cw from CWL) without 
  the need of a temp ts file.
- possibility for direct playing by passing the decrypted data to stdout. Does 
  this need anyone? 
- Only one service is allowed in the ts file. If encrypted packets from more 
  than one programs are present in the file (e.g. full transponder recorded), 
  everything fails because tsdec does not (yet) consider the PMT/PAT.

------------------------------------------------------------------
TSDEC contains code from LIBDVBCSA and FFdecsa. Thanks to the authors!
TSDEC and its readme.txt is based on cwldec V0.0.2 from 2004. Thanks to the 
anonymous author.

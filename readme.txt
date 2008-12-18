#########
TSDEC
#########

What is TSDEC? 
TSDEC is a small tool for decrypting recorded DVB transport streams (*.ts) with 
the recorded control words from a CWL file. First of all have a look at the 
original CWLDEC readme below. Thanks to the anonymous author for that project!

TSDEC is a successor of cwldec and based on cwldec V0.0.2 from 2004
TSDEC contains code from LIBDVBCSA and FFdecsa. Thanks to the authors!
Greetings go to www.4freeboard.to. Thanks for the helpful discussions about 
cwldec.

differences to CWLDEC:
- TSDEC runs on windows not linux. Is is compiled with MS Visual C++ 2008. 
  Sources enclosed.
- TSDEC uses the CSA implementation from LIBDVBCSA project. CWLDEC uses its 
  own csa code which has problems with partly filled TS packets. Complete rework
  of syncing mechanism.
- TSDEC does some more plausibility checking of the TS file to be decrypted. 
- TSDEC can decrypt TS files with a constant CW. No CWL file is needed then. 
  Constant CW decryption may be used for recorded streams encrypted with 
  constant CW (which may be unknown at recording time).
- TSDEC can encrypt TS files with a constant CW.  
  Encryption with constant CW may be used for recordings from full featured DVB
  cards or set top boxes. Some devices with hardware based CSA decryption are 
  unable to record an encrypted TS without decrypting it (e.g. the dBox 2). 
  Unfortunately if no correct control word is available at that time, the 
  stream is "decrypted" with the wrong CW. Then you have to encrypt the stream
  first with the same wrong CW and decrypt it with the CWs from CWL.
- TSDEC supports cw blocking.
- TSDEC cannot write the decrypted data to stdout for now.

  
Things not yet implemented in TSDEC
- usage of the csa bitslice implementation (FFdecsa) of LIBDVBCSA for speed up.
- on the fly encryption (constant CW) -> decryption (cw from CWL) without 
  the need of a temp ts file.
- check for further PUSI packets after sucessful sync. Check if still synced.

How to use:
- logging of cws into cwl files:
  Users of set top boxes running a softcam (like camd3, mgcamd,...) may want to
  use the cwlog utility included in the CWlog directory. Tested with dbox2.
  I dont know if theres a way to log CWs with a DVB card. 
  The CWL must have CWs with alternating parity on each line! See example.cwl
- recording TS files:
  Works best with budget DVB cards. 
  With FF card or stb you may have the problems described above. If you're lucky
  tsdec will sync to cwl and your recorded TS can be decrypted as usual.
  If not, as a workaround you can encrypt the recorded TS with ccw before 
  decryptng it with the CWL. Therefore you have to know the CW used for 
  decryption. Try to record the TS without a softcam loaded and encrypt the TS 
  with 16 x 0x00 as CW. This works for dbox2!
  If this was successful, tsdec will sync in the 2nd step and you get a playable 
  TS file. Otherwise tsdec will not sync.
- decrypting TS files:
  The cw change blocker (-b) supresses the usage of a new cw from the CWL for 
  each parity if it happens after less than n packets. Useful for transmissions 
  where the parity toggles for a while when the cw changes. The value must be 
  decreased if the bit rate of the stream is very low (1000 packets per second 
  for a ~1.4 MBit stream) and if the CW changes very often. Use greater value if 
  parity toggles for a longer time and tsdec accidently uses the next cw from cwl 
  file. The decrypted stream would not be readable after that point. Default: 300
- playing the TS file:
  Use MPlayer or vlc.

Like cwldec, tsdec is also for educational purposes only. 
  
And now, have fun!  


 -------------------- original CWLDEC readme file --------------------
Remember "VCL" files from Videocrypt times? This is its successor for dvb
cards.

The idea:
One party with a valid subscription card records the decrypted control words
to a file, and makes them available later.
People without subscription record the encrypted video/audio streams, and
decode them later using the information found in the .cwl file.

This works for all systems where the cam<->card communication is not en-
crypted, or where the cam<->card encryption is known.
This would even work for Videoguard, once the cam<->card encryption becomes
public.


This simple program is the decoding part of the game.
It will descramble a scrambled recording thanks to a provided .cwl file:
   cwldec -f 040212-1159-30w-11851h-Sol.cwl -o decoded.ts encoded.ts

[The program tries to sync by checking for "00 00 01" in the header of packets
 where the payload-unit-start-indicator bit is set.]


You can record the scrambled streams for example under linux with:
   szap -r MCM &
   cat /dev/dvb/adapter0/dvr0 > encoded.ts


For the cw recording, the currently used plugins for windows/linux simply
have to add an option to also record the cws they set to a file as well on
request.
So, in SetCaDescriptor() only one line has to be added:
  fprintf(fpcwl, "%d %02x %02x %02x %02x %02x %02x %02x %02x\n"
  , parity, cw[0], cw[1], cw[2], cw[3], cw[4], cw[5], cw[6], cw[7]);

[You can also add something like:  "040220-1709-08 12226-002c-06fc"
(UTC date/time, frequency, sid, ecm-pid) to the line if you want.
cwldec isn't using these informations yet: it simply ignores everything
after the 8th byte of the cw.
]

I'm proposing this convention for .cwl file names:
  040212-1159-30w-11851h-Sol.cwl
that's: start date and time in UTC, sat pos., frequency/polar., channel name.


*** The .cwl file should start earlier than the recording of the encrypted
*** streams. Otherwise, the sync may need ages.
*** In other words: the control word needed to decrypt the first packet in the
*** encrypted recording should be present in the .cwl file.


The program is meant to produce decoded streams, it is not meant for
viewing encoded streams directly, even if this will work under most circum-
stances, like : cwldec -f file.cwl encrypted.ts | xine stdin:/
The standard procedure will be:
  cwldec -f file.cwl -o decrypted.ts encrypted.ts (and wait....)
  mplayer decrypted.ts
[And if you delete the cws used during advertisement breaks, you should
 get a stream without advertisement ;-) This idea is C hel ;-)]



Is CWL illegal?
I'm afraid it might be in most European countries.
Perhaps it isn't, because - of course - it is released for educational purposes
only. 

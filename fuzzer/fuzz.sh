#!/bin/bash

for i in {1..1000}
do
   #echo "Welcome $i times"
   cat SCFFile.tlv | radamsa > SCFFile.tlv
   wine SCFParser.exe SCFFile.tlv
done

#!/bin/bash

for i in {1..1000}
do
   #echo "Welcome $i times"
   cat SCFFile.tlv | radamsa > SCFFile.tlv
   if wine SCFParser.exe SCFFile.tlv ; then
	   cp SCFFile.tlv SCFFile-$i.tlv
	   echo "fuzz: $i crashed" >> results.txt
   else
	   echo "fuzz: $i passed" >> results.txt
   fi
done

#!/bin/sh

baudrate=115200
com="/dev/ttyUSB0"
logfile=$1

DEFAULT_COLOR="\033[0m"

ERROR_PATTERN="Unable"
ERROR_COLOR="\033[1;32;41m"
WARNING_PATTERN="Switch"
WARNING_COLOR="\033[1;30;40m"
INFO_PATTERN="USBH"
INFO_COLOR="\033[1;32m"

stty -F $com $baudrate cs8 -cstopb

# init the input file
echo "" > $1

while read line
do
	error=$(echo $line | grep $ERROR_PATTERN)
	warn=$(echo $line | grep $WARNING_PATTERN)
	info=$(echo $line | grep $INFO_PATTERN)
	if [ -n "$error" ]; then
		echo -e "$ERROR_COLOR$line$DEFAULT_COLOR"
		beep
	elif [ -n "$warn" ]; then
		echo -e "$WARNING_COLOR$line$WARNING_COLOR"
	elif [ -n "$info" ]; then
		echo -e "$INFO_COLOR$line$INFO_COLOR"
	else
		echo -e "$DEFAULT_COLOR$line"
	fi

	echo $line >> $1
done < $com

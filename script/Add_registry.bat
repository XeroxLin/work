@echo off
echo "Add IgnoreHWSerNum list"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbflags" /v IgnoreHWSerNum18d14EE7 /t REG_BINARY /d 01
pause

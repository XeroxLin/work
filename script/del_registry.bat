@echo off
echo "delete IgnoreHWSerNum registry"
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\usbflags" /v IgnoreHWSerNum18d14EE7 /f
pause

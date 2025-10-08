#!/bin/sh -x
adb shell su 0 stop
sleep 1s
adb shell su 0 rm /data/system/install_sessions.xml
adb shell su 0 rm -rf '/data/app/vmdl*.tmp'
adb shell su 0 start

@echo off
if not exist kernel mkdir kernel
if not exist kernel\driver mkdir kernel\driver
if not exist kernel\core mkdir kernel\core
if not exist kernel\hooks mkdir kernel\hooks
if not exist kernel\process mkdir kernel\process
if not exist kernel\net mkdir kernel\net
if not exist kernel\file mkdir kernel\file
if not exist kernel\reg mkdir kernel\reg
if not exist kernel\keylog mkdir kernel\keylog
if not exist kernel\comm mkdir kernel\comm
if not exist usermode mkdir usermode
if not exist usermode\control mkdir usermode\control
if not exist usermode\installer mkdir usermode\installer
if not exist usermode\panel mkdir usermode\panel
if not exist includes mkdir includes
if not exist libs mkdir libs
if not exist build mkdir build
if not exist output mkdir output
echo project structure created successfully
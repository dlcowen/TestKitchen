import pytsk3
import sys
import json
import struct
import binascii
import datetime
import csv
img = pytsk3.Img_Info('\\\\.\\C:')
fs = pytsk3.FS_Info(img)
fileobject = fs.open("/Users/Dave/NTUSER.DAT")
print("File Inode:",fileobject.info.meta.addr)
print("File Name:",fileobject.info.name.name)
print("File Creation Time:",datetime.datetime.fromtimestamp(fileobject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'))
outFileName = fileobject.info.name.name
print(outFileName)
outfile = open(outFileName, 'wb')
filedata = fileobject.read_random(0,fileobject.info.meta.size)
outfile.write(filedata)
outfile.close

fileobject = fs.open("/Users/Dave/NTUSER.DAT.Log1")
print("File Inode:",fileobject.info.meta.addr)
print("File Name:",fileobject.info.name.name)
print("File Creation Time:",datetime.datetime.fromtimestamp(fileobject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'))
outFileName = fileobject.info.name.name
print(outFileName)
outfile = open(outFileName, 'wb')
filedata = fileobject.read_random(0,fileobject.info.meta.size)
outfile.write(filedata)
outfile.close

fileobject = fs.open("/Users/Dave/NTUSER.DAT.Log2")
print("File Inode:",fileobject.info.meta.addr)
print("File Name:",fileobject.info.name.name)
print("File Creation Time:",datetime.datetime.fromtimestamp(fileobject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'))
outFileName = fileobject.info.name.name
print(outFileName)
outfile = open(outFileName, 'wb')
filedata = fileobject.read_random(0,fileobject.info.meta.size)
outfile.write(filedata)
outfile.close
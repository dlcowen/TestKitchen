import pytsk3
import sys
import json
import struct
import binascii
import datetime
import csv

class ObjectId(object):
    def __init__(self, buf):
        self._buffer = buf

    @property
    def timestamp(self):
        # http://computerforensics.parsonage.co.uk/downloads/TheMeaningofLIFE.pdf
        # The file ObjectID is a time based version which means it is created using a system time.
        # The time is a 60 bit time value, a count of 100 nanosecond intervals of UTC since midnight
        # at the start of 15th October 1582.

        # Get le uint64
        le_timestamp = struct.unpack("<Q", self._buffer[0:8])[0]

        # remove first 4 bits used for version
        le_timestamp = le_timestamp - (le_timestamp & 0xf000000000000000)

        # see http://computerforensics.parsonage.co.uk/downloads/TheMeaningofLIFE.pdf
        le_timestamp = le_timestamp - 5748192000000000

        # get timestamp
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=le_timestamp / 10)

    @property
    def rawtimestamp(self):
        le_timestamp = struct.unpack("<Q", self._buffer[0:8])[0]
        return le_timestamp

    @property
    def version(self):
        high_order = struct.unpack(">H", self._buffer[6:8])[0]
        return high_order & 0x000f

    @property
    def variant(self):
        field = struct.unpack(">H", self._buffer[8:10])[0]
        return field >> 14

    @property
    def sequence(self):
        field = struct.unpack(">H", self._buffer[8:10])[0]
        return field & 0x3FFF

    @property
    def mac(self):
        return binascii.hexlify(self._buffer[10:16])



def printOBJID(file_entry, fullpath):
    for attribute in file_entry:
        if attribute.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_OBJID:
            rawoid = file_entry.read_random(0, 16, attribute.info.type, attribute.info.id)
            print(binascii.hexlify(rawoid), fullpath)
            object_id = ObjectId(rawoid)
            wr.writerow([fullpath,object_id.rawtimestamp, object_id.timestamp, datetime.datetime.fromtimestamp(file_entry.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'),object_id.mac,object_id.version, object_id.variant, object_id.sequence,file_entry.info.meta.addr,file_entry.info.meta.seq ])
            return


def directoryRecurse(directoryObject, parentPath):
    for entryObject in directoryObject:
        #print ("entry ", entryObject.info.name.name.decode("utf-8"))
        if entryObject.info.name.name.decode("utf-8") in [".", ".."]:
            continue

        try:
            f_type = entryObject.info.meta.type
        except:
            #print("Cannot retrieve type of", entryObject.info.name.name.decode("utf-8"))
            continue

        try:

            filepath = '/%s/%s' % ('/'.join(parentPath),entryObject.info.name.name.decode("utf-8"))
            #print("path ", filepath)
            if f_type == pytsk3.TSK_FS_META_TYPE_DIR:
                sub_directory = entryObject.as_directory()
                parentPath.append(entryObject.info.name.name.decode("utf-8"))
                printOBJID(entryObject, filepath)
                directoryRecurse(sub_directory, parentPath)
                parentPath.pop(-1)

            elif f_type == pytsk3.TSK_FS_META_TYPE_REG and entryObject.info.meta.size != 0:
                printOBJID(entryObject, filepath)

            elif f_type == pytsk3.TSK_FS_META_TYPE_REG and entryObject.info.meta.size == 0:
                printOBJID(entryObject, filepath)


        except IOError as e:
            print(e)
            continue


img = pytsk3.Img_Info('\\\\.\\C:')
fs = pytsk3.FS_Info(img)
outfile = open('objectids.csv','w')
outfile.write('"Full Path","ObjectID Raw Timestamp", "ObjectID Timestamp","Filesystem creation","ObjectID MAC","ObjectID Version","ObjectID Variant","ObjectID Sequence","File Entry", "Sequence"\n')
wr = csv.writer(outfile, quoting=csv.QUOTE_ALL)

directoryObject = fs.open_dir(path="/")
directoryRecurse(directoryObject, [])
fileobject = fs.open("/$MFT")
print("File Inode:",fileobject.info.meta.addr)
print("File Name:",fileobject.info.name.name)
print("File Creation Time:",datetime.datetime.fromtimestamp(fileobject.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'))
outFileName = fileobject.info.name.name
print(outFileName)
outfile = open(outFileName, 'wb')
filedata = fileobject.read_random(0,fileobject.info.meta.size)
outfile.write(filedata)
outfile.close

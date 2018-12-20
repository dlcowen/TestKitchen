import pytsk3
from struct import *

def fullPath(parent):
	parent_entry = unpack("<Lxx", parent[:6])[0]
	parent_seq = unpack("<H", parent[6:8])[0]
	if parent_entry == 5:
		return("")
	dir_entry = fs.open_meta(inode=parent_entry)
	for attribute in dir_entry:
		if attribute.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME:
			filenamelength = dir_entry.read_random(64, 1, attribute.info.type, attribute.info.id)		
			filename = dir_entry.read_random(66, int.from_bytes(filenamelength, byteorder='little')*2, attribute.info.type, attribute.info.id)		
			parent_ref = dir_entry.read_random(0, 8, attribute.info.type, attribute.info.id)
			parent_path = fullPath(parent_ref)
			parent_name = parent_path + "/" + filename.decode("utf-16", "ignore")
			return parent_name
	
img = pytsk3.Img_Info('\\\\.\\C:')
fs = pytsk3.FS_Info(img)

lines = [line.rstrip('\n') for line in open('UpdatedNumsAndSeqs.txt')]

for line in lines:
	entry, seq, programID = line.split('\t')
	file_entry = fs.open_meta(inode=int(entry))
	current_seq = file_entry.info.meta.seq
	if int(current_seq) == int(seq):
		samefile = 'Yes'
	else:
		samefile = 'No'
	
	for attribute in file_entry:
		if attribute.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME:
			filenamelength = file_entry.read_random(64, 1, attribute.info.type, attribute.info.id)		
			filename = file_entry.read_random(66, int.from_bytes(filenamelength, byteorder='little')*2, attribute.info.type, attribute.info.id)	
			namespace = file_entry.read_random(65, 1, attribute.info.type, attribute.info.id)	
			parent_ref = file_entry.read_random(0, 8, attribute.info.type, attribute.info.id)	
			parentPath = fullPath(parent_ref)
			print(line,"\t",int.from_bytes(namespace, byteorder='little'),"\t",filename.decode("utf-16", "ignore"),"\t",samefile,"\t",current_seq,"\t",parentPath)
			
	
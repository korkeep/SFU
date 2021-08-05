import sys
import struct
import os

filename = ["boot.tar",
            "opt.tar",
            "documentation.tar"]
fwrite = open("enFW","wb")

for f in filename:
    fsize = os.path.getsize(f)
    fp = open(f, "rb")
    fwrite.write(struct.pack("<i", len(f)))
    fwrite.write(f.encode())
    fwrite.write(struct.pack("<i",fsize))
    fwrite.write(fp.read())
    fp.close()


# doomwad.py: Doom WAD file library
#
# Copyright (c) 2009 Jared Stafford (jspenguin@gmail.com)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Read and write Doom WAD files"""

import struct
from io import StringIO

_header = struct.Struct("<4sII")
_dirent = struct.Struct("<II8s")

# Map members
specnames = {
    'THINGS',
    'VERTEXES',
    'LINEDEFS',
    'SIDEDEFS',
    'SEGS',
    'SSECTORS',
    'NODES',
    'SECTORS',
    'REJECT',
    'BLOCKMAP',
    'BEHAVIOR',
    'SCRIPTS'
}


class Lump(object):
    def __init__(self, name, data, index=None):
        self.name = name
        self.data = data
        self.index = index
        self.marker = data == "" and name not in specnames


class WadFile(object):
    def __init__(self, data_or_file):
        if hasattr(data_or_file, 'read') and \
                hasattr(data_or_file, 'seek'):
            file = data_or_file
        else:
            file = StringIO(data_or_file)

        sig, numentries, offset = _header.unpack(file.read(12))

        if sig != 'IWAD' and sig != 'PWAD':
            raise ValueError('not a WAD file')

        self.sig = sig

        file.seek(offset, 0)
        direct = file.read(16 * numentries)

        lumps = []

        for i in range(numentries):
            pos = i * 16
            offset, size, name = _dirent.unpack(direct[pos: pos + 16])
            idx = name.find('\0')
            if idx != -1:
                name = name[:idx]

            if size:
                file.seek(offset, 0)
                data = file.read(size)
            else:
                data = ""

            lumps.append(Lump(name.upper(), data, i))

        self.lumps = lumps

    def writeto(self, file):
        directory = []
        dirsize = 16 * len(self)

        pos = 12

        for lump in self:
            lsize = len(lump.data)
            directory.append((lump.name, pos, lsize))
            pos += lsize

        file.write(_header.pack(self.sig, len(self), pos))
        for lump in self:
            file.write(lump.data)

        for name, pos, size in directory:
            file.write(_dirent.pack(pos, size, name))

    # Simple linear search works fine: there are usually
    # only a few hundred lumps in a file.
    def find(self, name, marker=None):
        idx = 0
        if marker:
            idx = marker.index + 1

        name = name.upper()
        end = len(self.lumps)
        while idx < end:
            lump = self.lumps[idx]
            if lump.name == name:
                return lump

            # Is this another marker lump?
            if marker and lump.marker:
                return None
            idx += 1
        return None

    def findmarker(self, lump):
        idx = lump.index
        while idx >= 0:
            lump = self.lumps[idx]
            if lump.marker:
                return lump

            idx -= 1
        return None

    def _reindex(self, start=0):
        for i in range(start, len(self.lumps)):
            self.lumps[i].index = i

    def removelump(self, lump):
        idx = lump.index
        self.lumps.remove(idx)
        self._reindex(idx)

    def insert(self, lump, before=None):
        idx = (before.index if before else len(self.lumps))
        lump.index = idx
        self.lumps.insert(idx, lump)
        self._reindex(idx + 1)

    def append(self, lump):
        self.insert(lump)

    def __getitem__(self, name):
        if isinstance(name, int):
            return self.lumps[name]

        names = name.split('/')
        lump = None
        for n in names:
            lump = self.find(n, lump)
        return lump

    def __len__(self):
        return len(self.lumps)

    def __iter__(self):
        return iter(self.lumps)


parsers = {}


def readarray(stream, clas):
    if isinstance(stream, Lump):
        stream = stream.data

    if isinstance(stream, str):
        stream = StringIO(stream)

    ret = []
    ssize = clas.size
    while True:
        dat = stream.read(ssize)
        if len(dat) < ssize:
            break

        ret.append(clas.fromstr(dat))
    return ret


def writearray(stream, array):
    for item in array:
        stream.write(str(item))


def _defparser(name, sdef, *members):
    mstruct = struct.Struct(sdef)

    class DataType(object):
        size = mstruct.size

        def __init__(self, *args, **kwargs):
            for i, v in enumerate(args):
                setattr(self, members[i], v)

            for k, v in kwargs.items():
                setattr(self, k, v)

        def _toseq(self):
            return [getattr(self, n) for n in members]

        def __str__(self):
            return mstruct.pack(*self._toseq())

        def __repr__(self):
            return '%s(%s)' % (name, ', '.join('%s=%r' % (n, getattr(self, n))
                                               for n in members))

        @staticmethod
        def fromstr(string):
            return DataType(*mstruct.unpack(string[:mstruct.size]))

    DataType.members = members
    DataType.__name__ = name
    globals()[name] = DataType


# TODO: finish other structures
_defparser('Vertex', '<hh', 'x', 'y')
_defparser('Thing', '<hhhhH', 'x', 'y', 'angle', 'type', 'flags')
_defparser('HexThing', '<hhhhhhHBBBBBB', 'id', 'x', 'y', 'height',
           'angle', 'type', 'flags', 'special', 'arg0', 'arg1',
           'arg2', 'arg3', 'arg4')
_defparser('Linedef', '<HHHHHhh', 'start_vtx', 'end_vtx', 'flags',
           'special', 'sector_tag', 'right_sdef', 'left_sdef')
_defparser('HexLinedef', '<HHHBBBBBBhh', 'start_vtx', 'end_vtx',
           'flags', 'special', 'arg0', 'arg1', 'arg2', 'arg3',
           'arg4', 'right_sdef', 'left_sdef')

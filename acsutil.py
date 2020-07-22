# acsutil.py: ZDoom ACS utilities module
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

"""ZDoom ACS utilities"""

import struct
import copy
import sys

from collections import deque

SIG_OLD = b'ACS\0'
SIG_NEW_LITTLE = b'ACSe'
SIG_NEW_BIG = b'ACSE'


def _fmtrw(fmt):
    str = struct.Struct("<" + fmt)
    pack = str.pack
    unpack = str.unpack
    size = str.size

    del str

    def retw(self, *dats):
        for dat in dats:
            self.write(pack(dat))

    def retr(self):
        dat = self.read(size)
        if len(dat) < size:
            raise EOFError()
        return unpack(dat)[0]

    def retg(dat, pos):
        dat = dat[pos: pos + size]
        if len(dat) < size:
            raise EOFError()
        return unpack(dat)[0]

    return retw, retr, retg


writeub, readub, getub = _fmtrw("B")
writeus, readus, getus = _fmtrw("H")
writeui, readui, getui = _fmtrw("I")

writesb, readsb, getsb = _fmtrw("b")
writess, readss, getss = _fmtrw("h")
writesi, readsi, getsi = _fmtrw("i")


def getstr(data, pos, len):
    return data[pos: pos + len]


def escapestr(str):
    # ACC seems to store the strings raw
    return '"%s"' % str


def read_chunks(data, pos, end, markers):
    chunks = {}
    while pos < end:
        cid = getstr(data, pos, 4)
        csize = getui(data, pos + 4)
        markers.append(Marker(pos, 'Chunk %r' % str(cid, encoding='ascii', errors='ignore')))
        pos += 8
        chunks.setdefault(cid, []).append(data[pos: pos + csize])
        pos += csize

    return chunks


def read_strings(data, pos, ipos):
    strings = []
    numstrings = getui(data, pos)
    for i in range(numstrings):
        spos = getui(data, ipos)
        ipos += 4

        epos = data.find(b'\0', spos)
        if epos != -1:
            cstr = data[spos: epos]
        else:
            cstr = ''
        strings.append(cstr)
    return strings


def find_strings_pos(data, pos):
    numstrings = getui(data, pos)
    pos += 4

    result = -1

    for _ in range(numstrings):
        result = min(getui(data, pos), result)
        pos += 4

    return result


def read_array(data, scode, ipos=0):
    if not data:
        return
    if isinstance(data, list):
        data = data[0]

    struc = struct.Struct('<' + scode)
    size = struc.size
    cnt = (len(data) - ipos) // size
    for i in range(cnt):
        yield (i,) + struc.unpack(data[ipos: ipos + size])
        ipos += size


class Marker(object):
    executable = False

    def __init__(self, ptr, label=None):
        self.label = label
        self.ptr = ptr
        self.end = ptr
        self.data = ''
        self.little = False

    def disassemble(self):
        yield '%10d: %s' % (self.ptr, self.getlabel())
        if self.data and self.executable:
            little = self.little
            end = self.end
            io = ScriptIO(self.data, little, self.ptr, end)
            io.begin = 0
            try:
                npcodes = len(pcodes)
                while io.addr < end:
                    addr = io.addr

                    if little:
                        pcd = readub(io)
                        if pcd >= 240:
                            pcd = 240 + ((pcd - 240) << 8) + readub(io)
                    else:
                        pcd = readui(io)

                    if pcd >= npcodes:
                        yield '  %10d: UNKNOWN %d' % (addr - io.begin, pcd)
                        continue

                    yield '  %10d: %s' % (addr - io.begin, pcodes[pcd].disassemble(io))


            except EOFError:
                pass
            yield ''

    def getlabel(self):
        return self.label


class Script(Marker):
    executable = True

    def __init__(self, ptr, num, type, argc):
        Marker.__init__(self, ptr)
        self.num = num
        self.type = type
        self.argc = argc
        self.flags = 0

    def get_type(self):
        try:
            return script_types[self.type] or "UNKNOWN"
        except IndexError:
            return "UNKNOWN"

    def getlabel(self):
        return 'script %d, type = %d (%s), flags = %04x, argc = %d' % \
               (self.num, self.type, self.get_type(), self.flags, self.argc)

    def getheader(self):
        if self.argc:
            argstr = '(%s)' % ', '.join('int local%d' % i for i in range(self.argc))
        else:
            argstr = '(void)'

        if self.type > 0:
            if self.argc:
                argstr = '%s %s' % (argstr, self.get_type())
            else:
                argstr = self.get_type()
        return 'script %d %s // addr = %d, flags=%04x' % \
               (self.num, argstr, self.ptr, self.flags)

    def __repr__(self):
        return 'Script(%d, %d, %d, %d)' % (self.num, self.type, self.ptr, self.argc)


class Function(Marker):
    executable = True

    def __init__(self, ptr, idx, argc, locals, hasreturn, importnum):
        Marker.__init__(self, ptr, 'function %d (%d, %d, %d) -> %d' %
                        (idx, argc, locals, importnum, hasreturn))
        self.idx = idx

        self.argc = argc
        self.locals = locals
        self.isvoid = not hasreturn
        self.importnum = importnum
        if not self.ptr:
            self.executable = False

    def getheader(self):
        firstvar = 0
        if self.argc:
            argstr = '(%s)' % ', '.join('int local%d' % i for i in range(self.argc))
        else:
            argstr = '(void)'
        return 'function %s func%d %s // addr = %d' % \
               (('void' if self.isvoid else 'int'), self.idx, argstr, self.ptr)


class ScriptIO(object):
    def __init__(self, data, little, addr=0, end=0):
        self.data = data
        self.little = little
        self.begin = addr
        self.addr = addr
        self.end = end

    def read(self, n):
        addr = self.addr
        end = min(self.end, addr + n)
        dat = self.data[addr: end]
        self.addr = addr + len(dat)
        return dat

    def seek(self, n):
        self.addr = n

    def tell(self):
        return self.addr

    def wordalign(self):
        self.addr = (self.addr + 3) & ~3


class ArrayInfo(object):
    """Describes an array read from an 'ARAY' chunk."""

    def __init__(self, index, nelem):
        self.index = index
        self.nelem = nelem
        self.elems = [0] * nelem

    def __repr__(self):
        return 'Array(%d, %r)' % (self.index, self.elems)


class VariableSet(object):
    def __init__(self, clas):
        self.vars = {}
        self.clas = clas

    def getvar(self, id):
        if id in self.vars:
            return self.vars[id]
        var = self.vars[id] = self.clas(id)
        return var


class Behavior(object):
    """Parses a compiled ACS object."""

    def __init__(self, data):
        strings = []
        self.scripts = scripts = []
        self.functions = functions = []
        self.scriptnum = scriptnum = {}

        self.vars = {}
        for vt in [GlobalVar, MapVar, WorldVar]:
            self.vars[vt.type] = VariableSet(vt)

        mapvars = self.vars['map']

        sig = getstr(data, 0, 4)
        datalen = len(data)
        dirofs = getui(data, 4)
        self.markers = markers = []
        is_intermediate = True
        chunkofs = dirofs

        if sig == SIG_OLD:
            is_intermediate = False

            if dirofs >= 24:
                chunkofs = datalen
                pretag = getstr(data, dirofs - 4, 4)
                if pretag == SIG_NEW_LITTLE or pretag == SIG_NEW_BIG:
                    sig = pretag
                    chunkofs = getui(data, dirofs - 8)
                    datalen = dirofs - 1

        self.little = sig == SIG_NEW_LITTLE

        if sig == SIG_OLD:
            markers.append(Marker(dirofs, 'Script table'))
            numscripts = getui(data, dirofs)
            ipos = dirofs + 4

            for i in range(numscripts):
                snum = getui(data, ipos)
                ptr = getui(data, ipos + 4)
                argc = getui(data, ipos + 8)
                ipos += 12

                num = snum % 1000
                type = snum // 1000
                cscript = Script(ptr, num, type, argc)
                scripts.append(cscript)
                markers.append(cscript)

                scriptnum[num] = cscript

            stringtable = dirofs + getui(data, dirofs) * 12 + 4
            strings = read_strings(data, stringtable, stringtable + 4)
            markers.append(Marker(stringtable, 'String table'))

            stringspos = find_strings_pos(data, stringtable)
            if stringspos != -1:
                markers.append(Marker(stringspos, 'Strings'))
        else:
            chunks = read_chunks(data, chunkofs, datalen, markers)
            estrings = chunks.get(b'STRE')
            ustrings = chunks.get(b'STRL')

            if ustrings:
                strings = read_strings(ustrings[0], 4, 12)

            for i, argcount, localcount, hasreturnval, importnum, ptr in \
                    read_array(chunks.get(b'FUNC'), 'BBBBI'):
                cfunc = Function(ptr, len(functions), argcount, localcount,
                                 hasreturnval, importnum)

                functions.append(cfunc)
                markers.append(cfunc)

            if is_intermediate:
                for i, num, type, addr, argc in \
                        read_array(chunks.get(b'SPTR'), 'HHII'):
                    cscript = Script(addr, num, type, argc)
                    scriptnum[num] = cscript
                    markers.append(cscript)
            else:
                for i, num, type, argc, addr in \
                        read_array(chunks.get(b'SPTR'), 'HBBI'):
                    cscript = Script(addr, num, type, argc)
                    scriptnum[num] = cscript
                    markers.append(cscript)

            mvar_init_data = chunks.get(b'MINI', [None])[0]
            if mvar_init_data:
                cvar = getui(mvar_init_data, 0)
                for i, mvar in read_array(mvar_init_data, 'i', 4):
                    mapvars.getvar(i + cvar).initval = mvar

            for i, num, size in \
                    read_array(chunks.get(b'ARAY'), 'II'):
                mvar = mapvars.getvar(num)
                mvar.isarray = True
                mvar.initval = [0] * size

            for idata in chunks.get(b'AINI', []):
                anum = getui(idata, 0)
                try:
                    mvar = mapvars.getvar(anum)
                    elem = mvar.initval
                    if isinstance(elem, list):
                        for i, val in read_array(idata, 'i', 4):
                            elem[i] = val
                except (KeyError, IndexError, AttributeError):
                    pass

            for i, num, flags in \
                    read_array(chunks.get(b'SFLG'), 'HH'):

                try:
                    scriptnum[num].flags = flags
                except KeyError:
                    pass

        markers.append(Marker(len(data), 'End'))

        markers.sort(key=lambda m: m.ptr)

        for p in range(len(markers) - 1):
            cc = markers[p]
            cc.end = markers[p + 1].ptr
            cc.data = data
            cc.little = self.little
        self.strings = strings
        self.data = data

    def lookupvar(self, type, id):
        return self.vars[type].getvar(id)

    def decompile(self, addr):
        """Attempt to decompile script or function at addr.

        Returns an Interpreter object.
        """

        intp = Interpreter(self)
        intp.decompile(addr)
        return intp

    def getstring(self, val):
        """Attempt to convert a number to a string.

        If val can be converted to an integer and is a valid
        string index, returns the string enclosed in quotes,
        otherwise returns val converted to a string."""

        try:
            return escapestr(self.strings[int(val)])
        except Exception:
            return str(val)


class StackEmptyError(Exception):
    pass


class StackItem(object):
    constval = None

    def constvalue(self):
        return self.constval

    _next = None


class StackBottom(StackItem):
    pass


stackbottom = StackBottom()
StackBottom._next = stackbottom


class StackMark(StackItem):
    pass


class Expression(StackItem):
    _is_string = False

    def is_string(self):
        return self._is_string

    def lookupstring(self, p):
        return self

    def tocode(self, p):
        return '/* not implemented for %s */' % type(self).__name__

    def genlines(self, p):
        return (self.tocode(p) + ';',)

    def put_block(self, p, block):
        block.put(self)


class Block(Expression):
    label = None
    terminal = False

    def __init__(self, finish=None, *finish_args):
        self.statements = []
        self._finish = finish
        self._finish_args = finish_args

    def finish(self):
        if self._finish:
            self._finish(*self._finish_args)
        self._finish = self._finish_args = None

    def put(self, s):
        self.statements.append(s)

    def parse(self, p, tgt):
        inst = tgt.inst
        addr = tgt.addr
        if tgt.block != self and tgt.entries > 1:
            self.put(tgt)
            p.create_block(tgt, self.finish)
            return

        inst.parse_block(p, self)

    def genlines(self, p):
        for s in self.statements:
            for l in s.genlines(p):
                yield l


class Target(Expression):
    inst = None
    block = None
    entries = 1
    label = ''

    def __init__(self, addr):
        self.addr = addr

    def tocode(self, p):
        return p.goto_code(self)


class Instruction(Expression):
    pcode = None
    stack = None
    addr = 0
    next = None

    def __init__(self, pcode, stack, addr, next):
        Expression.__init__(self)
        self.addr = addr
        self.next = next
        self.pcode = pcode
        if stack:
            self.stack = stack

    def queue_target(self, p, tgt):
        p.queue(p.read_instruction, tgt, p.top)

    def parse(self, p, *args):
        self.queue_target(p, self.next)

    def parse_block(self, p, block):
        p.queue(block.parse, p, self.next)

    def disassemble(self):
        return self.pcode.name

    def normalize(self):
        return self


class Parser(ScriptIO):
    use_goto = True

    def __init__(self, behavior):
        ScriptIO.__init__(self, behavior.data, behavior.little, 0, len(behavior.data))
        self.behavior = behavior
        self.targets = {}
        self._queue = deque()
        self.top = stackbottom
        self._qid = 0
        self.locals = VariableSet(LocalVar)

    def lookuplocal(self, id):
        return self.locals.getvar(id)

    def lookupvar(self, type, id):
        return self.behavior.lookupvar(type, id)

    def goto_code(self, tgt):
        return 'goto %s' % tgt.label

    def restart_code(self):
        return 'restart'

    def target(self, addr):
        return self.targets.setdefault(addr, Target(addr))

    def pop(self, n=None):
        if n is None:
            top = self.top
            self.top = top._next
            return top

        ret = [None] * n
        for i in range(n - 1, -1, -1):
            ret[i] = self.pop()
        return ret

    def push(self, item):
        if item._next is not None and item._next is not self.top:
            item = copy.copy(item)
        item._next = self.top
        self.top = item

    def dup(self):
        self.push(copy.copy(self.top))

    def swap(self):
        v1 = self.pop()
        v2 = self.pop()
        self.push(v1)
        self.push(v2)

    def run(self):
        q = self._queue
        while q:
            id, func, args = q.popleft()
            try:
                func(*args)
            except:
                print('<failed id was %d>' % id)
                raise

    def queue(self, func, *args):
        # print 'Queue %d' % self._qid
        if self._qid == 30000:
            print(len(self._queue))
            raise ValueError
        self._queue.append((self._qid, func, args))
        self._qid += 1

    def read_instruction(self, tgt, stacktop):
        addr = tgt.addr
        if tgt.inst:
            tgt.entries += 1
            return

        self.addr = addr
        self.top = stacktop

        if self.little:
            pcd = readub(self)
            if pcd >= 240:
                pcd = 240 + ((pcd - 240) << 8) + readub(self)
        else:
            pcd = readui(self)

        if pcd >= len(pcodes):
            print("Unsupported pcode {}".format(pcd))
            pcd = pcodes[pcode_index['TERMINATE']]
        else:
            pcd = pcodes[pcd]

        instr = pcd.parse(self, addr)
        tgt.inst = instr

    def create_block(self, tgt, finish=None, *finish_args):
        if tgt.block:
            if finish:
                self.queue(finish, *finish_args)
        else:
            blk = Block(finish, *finish_args)
            tgt.block = blk
            self.queue(blk.parse, self, tgt)

    def create_sub_block(self, tgt, finish=None, *finish_args):
        blk = Block(finish, *finish_args)
        if tgt.entries > 1:
            blk.put(tgt)
            self.create_block(tgt, blk.finish)
        else:
            self.queue(blk.parse, self, tgt)
        return blk

    def read_instructions(self, addr):
        tgt = self.target(addr)
        self.read_instruction(tgt, stackbottom)
        tgt.entries += 1
        self.run()
        return tgt

    def getfunc(self, n):
        return self.behavior.functions[n]

    def getstring(self, n):
        return self.behavior.strings[int(n)]


class ConstantReference(Expression):
    def __init__(self, name, val):
        self.val = val
        self.name = name

    def constvalue(self):
        return self.val

    def tocode(self, p):
        return self.name


class StringLiteral(Expression):
    def __init__(self, val, id):
        Expression.__init__(self)
        self.val = val
        self.id = id

    def initargs(self):
        return (self.val,)

    def tocode(self, p):
        return escapestr(self.val)

    def disassemble(self):
        return str(self.id)

    def __repr__(self):
        return 'StringLiteral(%r)' % self.val


class Literal(Expression):
    def __init__(self, val):
        Expression.__init__(self)
        self.val = val

    def constvalue(self):
        return self.val

    def getexpr(self, p):
        return self

    def disassemble(self):
        return str(self.val)

    def lookupstring(self, p):
        try:
            return StringLiteral(p.getstring(self.val), self.val)
        except IndexError:
            return self

    def tocode(self, p):
        return '%d' % self.val

    def __repr__(self):
        return 'Literal(%r)' % self.val

    @classmethod
    def parse(cls, p, id):
        return cls(id)


class ArrayIndex(Expression):
    def __init__(self, arr, index):
        Expression.__init__(self)
        self.arr = arr
        self.index = index

    def lookupstring(self, p):
        self.arr = self.arr.lookupstring(p)
        return self

    def assignedby(self, p, a):
        self.arr.assignedby(p, a)

    def initargs(self):
        return (self.arr, self.index)

    def tocode(self, p):
        return '%s[%s]' % (self.arr.tocode(p), self.index.tocode(p))

    @classmethod
    def parse(cls, p, id, clas):
        avar = p.lookupvar(clas.type, id)
        avar.isarray = True
        return cls(avar, p.pop())


class Variable(Expression):
    initval = 0
    can_be_array = True
    isarray = False

    def __init__(self, id):
        Expression.__init__(self)
        self.id = id
        self.assigns = set()

    def lookupstring(self, p):
        if not self._is_string:
            self._is_string = True
            for a in self.assigns:
                a.make_string(p)
            self.assigns = None
        return self

    def assignedby(self, p, a):
        if self._is_string:
            a.make_string(p)
        else:
            self.assigns.add(a)

    def getexpr(self, p):
        return self

    def disassemble(self):
        return str(self.id)

    def tocode(self, p):
        return '%s%d' % (self.type, self.id)

    @classmethod
    def parse(cls, p, id):
        return p.lookupvar(cls.type, id)


class LocalVar(Variable):
    can_be_array = False
    opname = 'SCRIPT'
    type = 'local'

    @classmethod
    def parse(cls, p, id):
        return p.lookuplocal(id)


class MapVar(Variable):
    opname = 'MAP'
    type = 'map'


class WorldVar(Variable):
    opname = 'WORLD'
    type = 'world'


class GlobalVar(Variable):
    opname = 'GLOBAL'
    type = 'global'


class Push(Instruction):
    def parse(self, p, dargs, clas, *args):
        self.values = [clas.parse(p, v, *args) for v in dargs]
        for v in self.values:
            p.push(v)

        Instruction.parse(self, p)

    def disassemble(self):
        return '%s %s' % (self.pcode.name, ', '.join(v.disassemble() for v in self.values))


class Assign(Instruction):
    _is_string = False

    def parse(self, p, dargs, op, clas, *args):
        self.val = p.pop()
        self.dest = clas.parse(p, dargs[0], *args)
        self.op = op

        if op == '=':
            self.dest.assignedby(p, self)

        Instruction.parse(self, p)

    def make_string(self, p):
        if not self._is_string:
            self._is_string = True
            self.val = self.val.lookupstring(p)

    def parse_block(self, p, block):
        block.put(self)
        Instruction.parse_block(self, p, block)

    def disassemble(self):
        return '%s %s' % (self.pcode.name, self.dest.tocode(None))

    def tocode(self, p):
        return '%s %s %s' % (self.dest.tocode(p), self.op,
                             self.val.tocode(p))


class InPlaceUnary(Instruction):
    def parse(self, p, dargs, op, clas, *args):
        self.dest = clas.parse(p, dargs[0], *args)
        self.op = op

        Instruction.parse(self, p)

    def parse_block(self, p, block):
        block.put(self)
        Instruction.parse_block(self, p, block)

    def disassemble(self):
        return '%s %s' % (self.pcode.name, self.dest.tocode(None))

    def tocode(self, p):
        return '%s%s' % (self.dest.tocode(p), self.op)


bin_opers = {
    '+': lambda a, b: a + b,
    '-': lambda a, b: a - b,
    '*': lambda a, b: a * b,
    '/': lambda a, b: a // b,
    '%': lambda a, b: a % b,
    '|': lambda a, b: a | b,
    '&': lambda a, b: a & b,
    '^': lambda a, b: a ^ b,
    '<<': lambda a, b: a << b,
    '>>': lambda a, b: a >> b,
    '==': lambda a, b: int(a == b),
    '!=': lambda a, b: int(a != b),
    '<': lambda a, b: int(a < b),
    '<=': lambda a, b: int(a <= b),
    '>': lambda a, b: int(a > b),
    '>=': lambda a, b: int(a >= b),
    '&&': lambda a, b: int(a and b),
    '||': lambda a, b: int(a or b),
}

unary_opers = {
    '!': lambda a: int(not a),
    '~': lambda a: ~a,
    '-': lambda a: -a,
}


class BinOperator(Instruction):
    def parse(self, p, op):
        self.right = p.pop()
        self.left = p.pop()
        self.op = op

        rcv = self.right.constvalue()
        lcv = self.left.constvalue()
        if rcv is not None and lcv is not None:
            try:
                self.constval = bin_opers[op](lcv, rcv)
            except ZeroDivisionError:
                pass

        p.push(self)
        Instruction.parse(self, p)

    def tocode(self, p):
        return '(%s %s %s)' % (self.left.tocode(p), self.op,
                               self.right.tocode(p))


class UnaryOperator(Instruction):
    def parse(self, p, op):
        self.right = p.pop()
        self.op = op
        rcv = self.right.constvalue()
        if rcv is not None:
            try:
                self.constval = unary_opers[op](rcv)
            except ZeroDivisionError:
                pass

        p.push(self)
        Instruction.parse(self, p)

    def tocode(self, p):
        return '%s%s' % (self.op, self.right.tocode(p))


class Comment(Expression):
    def __init__(self, txt):
        self.txt = txt

    def tocode(self, p):
        return '/* %s */' % self.txt

    def __repr__(self):
        return 'Comment(%r)' % self.txt


class Terminal(Instruction):
    void = True

    def parse(self, p, name):
        self.name = name

    def parse_block(self, p, block):
        block.terminal = True
        ci = self.stack
        if ci is not stackbottom and not self.void:
            ci = ci._next

        while ci is not stackbottom:
            ci.put_block(p, block)
            ci = ci._next
        self.put_block(p, block)
        block.finish()

    def tocode(self, p):
        return self.name

    def __eq__(self, o):
        return isinstance(o, Terminal) and self.name == o.name


class Restart(Terminal):
    def tocode(self, p):
        return p.restart_code()


class Goto(Instruction):
    def parse(self, p, dargs):
        self.next = p.target(dargs[0])
        Instruction.parse(self, p)

    def parse_block(self, p, block):
        Instruction.parse_block(self, p, block)

    def disassemble(self):
        return self.pcode.name + ' %d' % self.next

    def normalize(self):
        next = self.next
        if next is None:
            self.next.inst = self
            return self

        self.next = None
        next.normalize()
        self.next = next
        return next.inst


class IfGoto(Instruction):
    neg = False
    nextblock = None
    tgtblock = None

    def parse(self, p, dargs):
        self.target = p.target(dargs[0])
        p.pop()
        self.queue_target(p, self.target)
        Instruction.parse(self, p)

    def parse_block(self, p, block):
        block.put(self)
        # print 'ifgoto %d parse_block %d' % (self.addr, self.next.addr)
        self.nextblock = p.create_sub_block(self.next, self.parse_tgtblock, p, block)

    def parse_tgtblock(self, p, block):
        # print 'ifgoto %d parse_tgtblock %d' % (self.addr, self.target.addr)
        self.tgtblock = p.create_sub_block(self.target, self.parse_finish, p, block)

    def parse_finish(self, p, block):
        # print 'ifgoto %d parse_finish' % self.addr
        nextblock = self.nextblock
        tgtblock = self.tgtblock

        common_statements = []
        nextstmts = nextblock.statements
        tgtstmts = tgtblock.statements
        if nextblock.terminal and tgtblock.terminal:
            block.terminal = True

        elif nextblock.terminal:
            # print 'next terminal:', self.next.addr
            block.statements.extend(tgtstmts)
            tgtstmts[:] = []

        elif tgtblock.terminal:
            # print 'tgt terminal:', self.target.addr
            block.statements.extend(nextstmts)
            nextstmts[:] = []
        else:
            while nextstmts and tgtstmts and \
                            nextstmts[-1] == tgtstmts[-1]:
                common_statements.append(nextstmts.pop())
                tgtstmts.pop()

        statements = block.statements

        common_statements.reverse()

        if common_statements:
            last = common_statements[-1]
            if isinstance(last, Target):
                # print 'Combining block at %d (%d)' % (target.addr, target.entries)
                last.entries -= 1
                if last.entries == 1:
                    common_statements.pop()
                    statements.extend(common_statements)
                    if last.block:
                        # If it's already been parsed, just add it
                        # to the current block
                        statements.extend(last.block.statements)
                        p.queue(block.finish)
                    else:
                        # Otherwise, queue it for parsing
                        statements.extend(common_statements)
                        p.queue(block.parse, p, last)
                    return

        p.queue(block.finish)
        statements.extend(common_statements)

    def genlines(self, p):
        elsblock = self.nextblock
        ifblock = self.tgtblock

        if self.neg:
            ifblock, elsblock = elsblock, ifblock

        if ifblock.statements:
            yield 'if (%s) {' % self.stack.tocode(p)

            for l in ifblock.genlines(p):
                yield '    ' + l

            if elsblock.statements:
                yield '} else {'
                for l in elsblock.genlines(p):
                    yield '    ' + l
            yield '}'
        else:
            yield 'if (!%s) {' % self.stack.tocode(p)
            for l in elsblock.genlines(p):
                yield '    ' + l
            yield '}'

    def disassemble(self):
        return self.pcode.name + ' %d' % self.target


class IfNotGoto(IfGoto):
    neg = True


class SwitchCase(object):
    def __init__(self, case, tgt):
        self.case = case
        self.target = tgt
        self.block = None


class SwitchExpr(Expression):
    def __init__(self, switch):
        self.switch = switch
        self.cases = []

    def addcase(self, case, tgt):
        self.cases.append(SwitchCase(case, tgt))

    def put_block(self, p, block):
        block.put(self)
        self.parse_case(p, block, 0)

    def parse_case(self, p, block, idx):
        if idx >= len(self.cases):
            return
        case = self.cases[idx]
        case.block = p.create_sub_block(case.target, self.parse_case,
                                        p, block, idx + 1)

    def genlines(self, p):
        yield 'switch (%s) {' % self.switch.tocode(p)
        for c in self.cases:
            yield '    case %d:' % c.case
            for l in c.block.genlines(p):
                yield '        %s' % l
        yield '}'


class CaseGoto(Instruction):
    def disassemble(self):
        return self.pcode.name + ' %d, %d' % (self.case, self.target.addr)

    def parse_cases(self, p, inst_args):
        self.case = inst_args[0]
        self.target = p.target(inst_args[1])
        self.switch.addcase(self.case, self.target)
        p.queue(p.read_instruction, self.target, p.top)

    def parse(self, p, inst_args):
        switch = p.pop()
        if not isinstance(switch, SwitchExpr):
            switch = SwitchExpr(switch)
        self.switch = switch

        self.parse_cases(p, inst_args)
        p.push(switch)
        Instruction.parse(self, p)


class CaseGotoSorted(CaseGoto):
    def disassemble(self):
        return self.pcode.name + ', '.join('%d: %d' % (c, t.target) for c, t in self.cases)

    def parse_cases(self, p, inst_args):
        self.cases = [(c, p.target(t)) for c, t in inst_args]
        for c, t in self.cases:
            self.switch.addcase(c, t)
            p.queue(p.read_instruction, t, p.top)


class Drop(Instruction):
    def parse(self, p):
        p.pop()
        Instruction.parse(self, p)

    def parse_block(self, p, block):
        self.stack.put_block(p, block)
        Instruction.parse_block(self, p, block)


class DupInst(Instruction):
    def parse(self, p):
        p.dup()
        Instruction.parse(self, p)


class TagString(Instruction):
    def parse(self, p):
        val = p.pop()
        p.push(val.lookupstring(p))
        Instruction.parse(self, p)


class SwapInst(Instruction):
    def parse(self, p):
        p.swap()
        Instruction.parse(self, p)


class PrintExpr(Expression):
    def __init__(self):
        self.items = []
        self.optargs = []
        self.name = 'UnknownPrint'

    def appenditem(self, item):
        self.items.append(item)
        return self

    def tocode(self, p):
        itemcode = ', '.join(i.tocode(p) for i in self.items)
        if self.optargs is not None:
            argcode = ', '.join(i.tocode(p) for i in self.optargs)
            return '%s(%s; %s)' % (self.name, itemcode, argcode)

        return '%s(%s)' % (self.name, itemcode)

    def finish(self, name, optargs=None):
        self.name = name
        self.optargs = optargs


class PrintItemExpr(Expression):
    def __init__(self, code, expr):
        self.code = code
        self.expr = expr


class BeginPrint(Instruction):
    def parse(self, p):
        p.push(PrintExpr())
        Instruction.parse(self, p)


class PrintItem(Instruction):
    def parse(self, p, code, *args):
        self.code = code
        self.val = self.interpret(p.pop(), p)
        pr = p.top
        try:
            pr.appenditem(self)
        except Exception:
            pass

        Instruction.parse(self, p)

    def tocode(self, p):
        return '%s:%s' % (self.code, self.val.tocode(p))

    @staticmethod
    def interpret(val, p):
        return val


class PrintString(PrintItem):
    @staticmethod
    def interpret(val, p):
        return val.lookupstring(p)


class PrintArray(PrintItem):
    pass


class CreateTranslation(Instruction):
    def parse(self, p):
        pi = PrintExpr()
        pi.appenditem(p.pop())
        p.push(pi)
        Instruction.parse(self, p)

    def interpret(self, p):
        pi = PrintExpr()
        pi.append(p.pop())
        p.push(pi)


class TranslationRange(Instruction):
    def tocode(self, p):
        args = tuple([e.tocode(p) for e in self.args])
        if len(args) == 8:
            return '%s:%s = [%s, %s, %s]:[%s, %s, %s]' % args
        return '%s:%s = %s:%s' % args

    def parse(self, p, nargs):
        self.args = p.pop(nargs)
        pr = p.top
        try:
            pr.appenditem(self)
        except Exception:
            pass
        Instruction.parse(self, p)


class EndPrint(Instruction):
    name = 'Unknown'

    def parse(self, p, name):
        self.name = name
        self.pi = p.pop()
        try:
            self.pi.finish(name)
        except Exception:
            pass
        Instruction.parse(self, p)

    def parse_block(self, p, block):
        block.put(self.pi)
        Instruction.parse_block(self, p, block)


class OptHudMessage(Instruction):
    def parse(self, p):
        p.push(StackMark())
        Instruction.parse(self, p)


class HudMessage(Instruction):
    def parse(self, p, name):
        self.name = name
        ci = p.top
        opt = []
        while ci is not stackbottom:
            if isinstance(ci, StackMark):
                p.top = ci._next
                break
            opt.append(ci)
            ci = ci._next
        else:
            opt = []

        opt.reverse()
        args = p.pop(6)

        self.pi = p.pop()
        try:
            self.pi.finish(self.name, args + opt)
        except Exception:
            pass
        Instruction.parse(self, p)

    def parse_block(self, p, block):
        block.put(self.pi)
        Instruction.parse_block(self, p, block)


class Call(Instruction):
    def tocode(self, p):
        return 'func%d(%s)' % (self.funcnum,
                               ', '.join(e.tocode(p) for e in self.args))

    def parse(self, p, inst_args, wantresult):
        funcnum = inst_args[0]
        func = p.getfunc(funcnum)
        args = p.pop(func.argc)

        self.funcnum = funcnum
        self.args = args
        self.wantresult = wantresult

        if wantresult:
            p.push(self)
        Instruction.parse(self, p)

    def parse_block(self, p, block):
        if(not(self.wantresult)):
            block.put(self)
        Instruction.parse_block(self, p, block)

    def disassemble(self):
        return '%s %d' % (self.pcode.name, self.funcnum)


class ReturnVoid(Terminal):
    def tocode(self, p):
        if not self.void:
            return 'return %s' % self.stack.tocode(p)
        return 'return'


class Return(ReturnVoid):
    void = False


class ArgumentInterpreter(object):
    def convert(self, p, args):
        for val in args:
            yield val


default_interp = ArgumentInterpreter()


class ConvStrings(ArgumentInterpreter):
    def __init__(self, *indices):
        self.indices = set(indices)

    def convert(self, p, args):
        for i, val in enumerate(args):
            if i in self.indices:
                try:
                    val = val.lookupstring(p)
                except Exception:
                    pass
            yield val


class ActorPropArgs(ArgumentInterpreter):
    def convert(self, p, args):
        val1 = args[0]
        valstring = False
        if isinstance(val1, Literal):
            try:
                name, valstring = aprop_names[val1.val]
                val1 = ConstantReference(name, val1.val)
            except Exception:
                pass


        val2 = args[1]
        if valstring:
            val2 = val2.lookupstring(val2)

        yield val2
        yield val1

        for i in args[2:]:
            yield i


class BuiltinCall(Instruction):
    def tocode(self, p):
        argcode = ', '.join(e.tocode(p) for e in self.args)
        if self.const:
            return '%s(const: %s)' % (self.name, argcode)
        return '%s(%s)' % (self.name, argcode)

    def parse(self, p, args, void, name, interp=default_interp):
        if isinstance(args, int):
            args = p.pop(args)
            const = False
        else:
            args = [Literal(v) for v in args]
            const = True

        self.name = name
        self.args = list(interp.convert(p, args))
        self.const = const
        self.void = void

        if not void:
            p.push(self)
        Instruction.parse(self, p)

    def parse_block(self, p, block):
        if self.void:
            block.put(self)
        Instruction.parse_block(self, p, block)

    def disassemble(self):
        if self.const:
            return '%s(%s) -> %d' % (self.name, ', '.join('%d' % v.val for v in self.args), int(not self.void))
        return '%s([%d]) -> %d' % (self.name, len(self.args), int(not self.void))


class LineSpec(BuiltinCall):
    def parse(self, p, inst_args, nargs, void=True):
        self.lspec = inst_args[0]
        specname = None
        if self.lspec < 255:
            specname = linespecials[self.lspec]

        if specname is None:
            specname = 'LineSpec%d' % self.lspec

        if nargs == 0:
            BuiltinCall.parse(self, p, inst_args[1:], void, specname)
        else:
            BuiltinCall.parse(self, p, nargs, void, specname)


class ArgCode(object):
    def __init__(self):
        pass

    def parse(self, s):
        return None

    def disassemble(self, s):
        return ()


class IntegerArgCode(ArgCode):
    def __init__(self, lfunc, bfunc=None):
        self.lfunc = lfunc
        self.bfunc = bfunc or lfunc

    def parse(self, s):
        return (self.lfunc if s.little else self.bfunc)(s)

    def disassemble(self, s):
        return ('%d' % self.parse(s),)


class VarArgCode(ArgCode):
    def _parse(self, s):
        cnt = readub(s)
        for i in range(cnt):
            yield readub(s)

    def parse(self, s):
        return list(self._parse(s))

    def disassemble(self, s):
        for i in self._parse(s):
            yield '%d' % s


class JumpTargetArgCode(ArgCode):
    def parse(self, s):
        return readui(s)

    def disassemble(self, s):
        tgt = readui(s) - s.begin
        return ('%d' % tgt,)


argcodes = dict(
    I=IntegerArgCode(readui),
    V=IntegerArgCode(readub, readui),
    B=IntegerArgCode(readub),
    i=IntegerArgCode(readsi),
    v=IntegerArgCode(readsb, readsi),
    b=IntegerArgCode(readsb),
    J=JumpTargetArgCode())


class PCode(object):
    def __init__(self, name, clas, *args):
        self.name = name
        self.clas = clas
        self.args = args

    def create(self, p, addr):
        return self.clas(self, p.top, addr, p.target(p.addr))

    def parse(self, p, addr):
        ret = self.create(p, addr)
        ret.parse(p, *self.args)
        return ret

    def disassemble(self, s):
        return self.name


class ArgPCode(PCode):
    def __init__(self, name, codes, clas, *args):
        PCode.__init__(self, name, clas, *args)
        self.codes = [argcodes[c] for c in codes]

    def parse(self, p, addr):
        inst_args = [ac.parse(p) for ac in self.codes]

        ret = self.create(p, addr)
        ret.parse(p, inst_args, *self.args)
        return ret

    def getargs(self, s):
        for ac in self.codes:
            for v in ac.disassemble(s):
                yield v

    def disassemble(self, s):
        return '%s %s' % (self.name, ', '.join(self.getargs(s)))


class CasePCode(PCode):
    def parse(self, p, addr):
        p.wordalign()
        numcases = readui(p)
        cases = [(readui(p), readui(p)) for i in range(numcases)]

        ret = self.create(p, addr)
        ret.parse(p, cases, *self.args)
        return ret

    def disassemble(self, s):
        s.wordalign()
        numcases = readui(s)
        return self.name + ' ' + ', '.join('%d: %d' % (readui(s), readui(s) - s.begin) for i in range(numcases))


class PushBytesPCode(PCode):
    def parse(self, p, addr):
        cnt = readub(p)
        inst_args = [readub(p) for i in range(cnt)]

        ret = self.create(p, addr)
        ret.parse(p, inst_args, *self.args)
        return ret

    def getargs(self, s):
        cnt = readub(s)
        for v in range(cnt):
            yield '%d' % readub(s)

    def disassemble(self, s):
        return '%s %s' % (self.name, ', '.join(self.getargs(s)))


def genpcodes():
    pcodes = [None] * len(pcode_names)

    def addpcode(pcode):
        idx = pcode_index[pcode.name]
        pcode.index = idx
        pcodes[idx] = pcode

    def pcode(*args):
        addpcode(PCode(*args))

    def apcode(*args):
        addpcode(ArgPCode(*args))

    def builtin_stack(name, arg, void=True, interp=default_interp):
        pcode(name.upper(), BuiltinCall, arg, void, name, interp)

    def builtin_direct(name, arg, void=True, interp=default_interp):
        apcode(name.upper() + 'DIRECT', 'I' * arg, BuiltinCall, void, name, interp)

    def builtin_both(name, arg, void=True, interp=default_interp):
        builtin_stack(name, arg, void, interp)
        builtin_direct(name, arg, void, interp)

    pcodenames = {}

    def byname(name):
        addpcode(pcodenames[name])

    pcode('NOP', Instruction)

    builtin_stack('Suspend', 0)
    pcode('TERMINATE', Terminal, 'Terminate')
    pcode('RESTART', Restart, 'Restart')

    # Functions
    apcode('CALL', 'V', Call, True)
    apcode('CALLDISCARD', 'V', Call, False)
    apcode('CALLFUNC', 'V', Call, True)
    pcode('RETURNVOID', ReturnVoid, 'return')
    pcode('RETURNVAL', Return, 'return')

    # Stack ops
    pcode('DUP', DupInst)
    pcode('SWAP', SwapInst)
    pcode('TAGSTRING', TagString)

    apcode('PUSHNUMBER', 'I', Push, Literal)
    apcode('PUSHBYTE', 'B', Push, Literal)
    apcode('LSPEC1DIRECTB', 'VB', LineSpec, 0)
    apcode('LSPEC2DIRECTB', 'VBB', LineSpec, 0)
    apcode('LSPEC3DIRECTB', 'VBBB', LineSpec, 0)
    apcode('LSPEC4DIRECTB', 'VBBBB', LineSpec, 0)
    apcode('LSPEC5DIRECTB', 'VBBBBB', LineSpec, 0)
    apcode('DELAYDIRECTB', 'B', BuiltinCall, True, 'Delay')
    apcode('RANDOMDIRECTB', 'BB', BuiltinCall, False, 'Random')

    addpcode(PushBytesPCode('PUSHBYTES', Push, Literal))
    apcode('PUSH2BYTES', 'BB', Push, Literal)
    apcode('PUSH3BYTES', 'BBB', Push, Literal)
    apcode('PUSH4BYTES', 'BBBB', Push, Literal)
    apcode('PUSH5BYTES', 'BBBBB', Push, Literal)

    apcode('LSPEC1', 'V', LineSpec, 1)
    apcode('LSPEC2', 'V', LineSpec, 2)
    apcode('LSPEC3', 'V', LineSpec, 3)
    apcode('LSPEC4', 'V', LineSpec, 4)
    apcode('LSPEC5', 'V', LineSpec, 5)
    apcode('LSPEC6', 'V', LineSpec, 6)
    apcode('LSPEC1DIRECT', 'VI', LineSpec, 0)
    apcode('LSPEC2DIRECT', 'VII', LineSpec, 0)
    apcode('LSPEC3DIRECT', 'VIII', LineSpec, 0)
    apcode('LSPEC4DIRECT', 'VIIII', LineSpec, 0)
    apcode('LSPEC5DIRECT', 'VIIIII', LineSpec, 0)
    apcode('LSPEC6DIRECT', 'VIIIIII', LineSpec, 0)
    apcode('LSPEC5RESULT', 'V', LineSpec, 5, False)

    # Math
    pcode('ADD', BinOperator, '+')
    pcode('SUBTRACT', BinOperator, '-')
    pcode('MULTIPLY', BinOperator, '*')
    pcode('DIVIDE', BinOperator, '/')
    pcode('MODULUS', BinOperator, '%')
    pcode('EQ', BinOperator, '==')
    pcode('NE', BinOperator, '!=')
    pcode('LT', BinOperator, '<')
    pcode('GT', BinOperator, '>')
    pcode('LE', BinOperator, '<=')
    pcode('GE', BinOperator, '>=')
    pcode('ANDLOGICAL', BinOperator, '&&')
    pcode('ORLOGICAL', BinOperator, '||')
    pcode('ANDBITWISE', BinOperator, '&')
    pcode('ORBITWISE', BinOperator, '|')
    pcode('EORBITWISE', BinOperator, '^')
    pcode('NEGATELOGICAL', UnaryOperator, '!')
    pcode('NEGATEBINARY', UnaryOperator, '~')
    pcode('LSHIFT', BinOperator, '<<')
    pcode('RSHIFT', BinOperator, '>>')
    pcode('UNARYMINUS', UnaryOperator, '-')

    # Variables
    opsym = dict(ADD='+=', SUB='-=', MUL='*=', DIV='/=', MOD='%=',
                 AND='&=', OR='|=', EOR='^=', LS='<<=', RS='>>=',
                 ASSIGN='=')
    uopsym = dict(INC='++', DEC='--')

    vartypes = [LocalVar, MapVar, WorldVar, GlobalVar]

    for vt in vartypes:
        for nm, op in opsym.items():
            apcode(nm + vt.opname + 'VAR', 'V', Assign, op, vt)

        for nm, op in uopsym.items():
            apcode(nm + vt.opname + 'VAR', 'V', InPlaceUnary, op, vt)

        apcode('PUSH' + vt.opname + 'VAR', 'V', Push, vt)
        if vt.can_be_array:
            for nm, op in opsym.items():
                apcode(nm + vt.opname + 'ARRAY', 'V', Assign, op, ArrayIndex, vt)

            for nm, op in uopsym.items():
                apcode(nm + vt.opname + 'ARRAY', 'V', InPlaceUnary, op, ArrayIndex, vt)

            apcode('PUSH' + vt.opname + 'ARRAY', 'V', Push, ArrayIndex, vt)

    # Branches
    apcode('GOTO', 'J', Goto)
    apcode('IFGOTO', 'J', IfGoto)
    pcode('DROP', Drop)
    apcode('CASEGOTO', 'IJ', CaseGoto)
    apcode('IFNOTGOTO', 'J', IfNotGoto)
    addpcode(CasePCode('CASEGOTOSORTED', CaseGotoSorted))

    # Builtins
    builtin_both('Delay', 1, True)
    builtin_both('Random', 2, False)
    builtin_both('ThingCount', 2, False)
    builtin_both('TagWait', 1, True)
    builtin_both('PolyWait', 1, True)
    builtin_both('ChangeFloor', 2, True, ConvStrings(1))
    builtin_both('ChangeCeiling', 2, True, ConvStrings(1))
    builtin_stack('LineSide', 0, False)
    builtin_both('Scriptwait', 1, True)
    builtin_stack('ClearLineSpecial', 0, True)
    builtin_stack('SetThingSpecial', 7, True)

    builtin_stack('Playercount', 0, False)
    builtin_stack('GameType', 0, False)
    builtin_stack('GameSkill', 0, False)
    builtin_stack('Timer', 0, False)
    builtin_stack('SectorSound', 2, True, ConvStrings(0))
    builtin_stack('AmbientSound', 2, True, ConvStrings(0))
    builtin_stack('SoundSequence', 1, True, ConvStrings(0))
    builtin_stack('SetLineTexture', 4, True, ConvStrings(3))
    builtin_stack('SetLineBlocking', 2, True)
    builtin_stack('SetLineSpecial', 7, True)
    builtin_stack('ThingSound', 3, True, ConvStrings(1))
    builtin_stack('ActivatorSound', 2, True, ConvStrings(0))
    builtin_stack('LocalAmbientSound', 2, True, ConvStrings(0))
    builtin_stack('SetLineMonsterBlocking', 2, True)
    builtin_stack('PlayerBlueSkull', 0, False)
    builtin_stack('PlayerRedSkull', 0, False)
    builtin_stack('PlayerYellowSkull', 0, False)
    builtin_stack('PlayerMasterSkull', 0, False)
    builtin_stack('PlayerMasterCard', 0, False)
    builtin_stack('PlayerBlueCard', 0, False)
    builtin_stack('PlayerRedCard', 0, False)
    builtin_stack('PlayerYellowCard', 0, False)
    builtin_stack('PlayerYellowCard', 0, False)
    builtin_stack('PlayerBlackSkull', 0, False)
    builtin_stack('PlayerSilverSkull', 0, False)
    builtin_stack('PlayerGoldSkull', 0, False)
    builtin_stack('PlayerBlackCard', 0, False)
    builtin_stack('PlayerSilverCard', 0, False)
    builtin_stack('PlayerOnTeam', 0, False)
    builtin_stack('PlayerTeam', 0, False)
    builtin_stack('PlayerHealth', 0, False)
    builtin_stack('PlayerArmorPoints', 0, False)
    builtin_stack('PlayerFrags', 0, False)
    builtin_stack('PlayerExpert', 0, False)
    builtin_stack('BlueTeamCount', 0, False)
    builtin_stack('RedTeamCount', 0, False)
    builtin_stack('BlueTeamScore', 0, False)
    builtin_stack('RedTeamScore', 0, False)
    builtin_stack('IsOneFlagCTF', 0, False)
    builtin_stack('MusicChange', 2, True, ConvStrings(0))
    builtin_direct('ConsoleCommand', 3, True)
    builtin_stack('ConsoleCommand', 3, True)
    builtin_stack('SinglePlayer', 0, False)
    builtin_stack('FixedMul', 2, False)
    builtin_stack('FixedDiv', 2, False)
    builtin_both('SetGravity', 1, True)
    builtin_both('SetAirControl', 1, True)
    builtin_stack('ClearInventory', 0, True)
    builtin_both('GiveInventory', 2, True, ConvStrings(0))
    builtin_both('TakeInventory', 2, True, ConvStrings(0))
    builtin_both('CheckInventory', 1, False, ConvStrings(0))
    builtin_both('Spawn', 6, False, ConvStrings(0))
    builtin_both('SpawnSpot', 4, False, ConvStrings(0))
    builtin_both('SetMusic', 3, True, ConvStrings(0))
    builtin_both('LocalSetMusic', 3, True, ConvStrings(0))
    builtin_both('SetStyle', 1, True)
    builtin_both('SetFont', 1, True, ConvStrings(0))
    builtin_stack('FadeTo', 5, True)
    builtin_stack('FadeRange', 9, True)
    builtin_stack('CancelFade', 0, True)
    builtin_stack('PlayMovie', 1, False, ConvStrings(0))
    builtin_stack('SetFloorTrigger', 8, True)
    builtin_stack('SetCeilingTrigger', 8, True)
    builtin_stack('GetActorX', 1, False)
    builtin_stack('GetActorY', 1, False)
    builtin_stack('GetActorZ', 1, False)
    builtin_stack('GetPlayerInfo', 2, False)
    builtin_stack('ChangeLevel', 4, True, ConvStrings(0))
    builtin_stack('SectorDamage', 5, True, ConvStrings(2))
    builtin_stack('ReplaceTextures', 3, True, ConvStrings(0, 1))
    builtin_stack('GetActorPitch', 1, False)
    builtin_stack('SetActorPitch', 2, True)
    builtin_stack('SetActorState', 3, False, ConvStrings(1))
    builtin_stack('ThingDamage2', 3, False, ConvStrings(2))
    builtin_stack('UseInventory', 1, False, ConvStrings(0))
    builtin_stack('UseActorInventory', 2, False, ConvStrings(1))
    builtin_stack('CheckActorCeilingTexture', 2, False, ConvStrings(1))
    builtin_stack('CheckActorFloorTexture', 2, False, ConvStrings(1))
    builtin_stack('GetActorLightLevel', 1, False)
    builtin_stack('SetMugshotState', 1, True, ConvStrings(0))
    builtin_stack('ThingCountSector', 3, False, ConvStrings(0))
    builtin_stack('ThingCountNameSector', 3, False, ConvStrings(0))
    builtin_stack('CheckPlayerCamera', 1, False)
    builtin_stack('MorphActor', 7, False, ConvStrings(1, 2, 5, 6))
    builtin_stack('UnmorphActor', 2, False)
    builtin_stack('GetPlayerInput', 2, False)
    builtin_stack('ClassifyActor', 1, False)
    builtin_stack('WriteToIni', 3, True)
    builtin_stack('GetFromIni', 3, False)
    builtin_stack('sin', 1, False)
    builtin_stack('cos', 1, False)
    builtin_stack('VectorAngle', 2, False)
    builtin_stack('CheckWeapon', 1, False, ConvStrings(0))
    builtin_stack('SetWeapon', 1, False, ConvStrings(0))
    builtin_stack('SetMarineWeapon', 2, True)
    builtin_stack('SetActorProperty', 3, True, ActorPropArgs())
    builtin_stack('GetActorProperty', 2, False, ActorPropArgs())
    builtin_stack('PlayerNumber', 0, False)
    builtin_stack('ActivatorTid', 0, False)
    builtin_stack('SetMarineSprite', 2, True, ConvStrings(1))
    builtin_stack('GetScreenWidth', 0, False)
    builtin_stack('GetScreenHeight', 0, False)
    builtin_stack('Thing_Projectile2', 7, True)
    builtin_stack('StrLen', 1, False, ConvStrings(0))
    builtin_stack('SetHudSize', 3, True)
    builtin_stack('GetCVar', 1, False, ConvStrings(0))
    builtin_stack('SetResultValue', 1, True)
    builtin_stack('GetLineRowOffset', 0, False)
    builtin_stack('GetActorFloorZ', 1, False)
    builtin_stack('GetActorAngle', 1, False)
    builtin_stack('GetSectorFloorZ', 3, False)
    builtin_stack('GetSectorCeilingZ', 3, False)
    builtin_stack('GetSigilPieces', 0, False)
    builtin_stack('GetLevelInfo', 1, False)
    builtin_stack('ChangeSky', 2, True, ConvStrings(0, 1))
    builtin_stack('PlayerInGame', 1, False)
    builtin_stack('PlayerIsBot', 1, False)
    builtin_stack('SetCameraToTexture', 3, True, ConvStrings(1))
    builtin_stack('EndLog', 0)
    builtin_stack('GetAmmoCapacity', 1, False, ConvStrings(0))
    builtin_stack('SetAmmoCapacity', 2, True, ConvStrings(0))
    builtin_stack('SetActorangle', 2, True)
    builtin_stack('GrabInput', 2, True)
    builtin_stack('SetMousePointer', 3, True)
    builtin_stack('MoveMousePointer', 2, True)
    builtin_stack('SpawnProjectile', 7, True, ConvStrings(1))
    builtin_stack('GetSectorLightLevel', 1, False)
    builtin_stack('GetActorCeilingZ', 1, False)
    builtin_stack('SetActorPosition', 5, False)
    builtin_stack('ClearActorInventory', 1, True)
    builtin_stack('GiveActorInventory', 3, True, ConvStrings(1))
    builtin_stack('TakeActorInventory', 3, True, ConvStrings(1))
    builtin_stack('CheckActorInventory', 2, False, ConvStrings(1))
    builtin_stack('ThingCountName', 2, False, ConvStrings(0))
    builtin_stack('SpawnSpotFacing', 3, False, ConvStrings(0))
    builtin_stack('PlayerClass', 1, False)
    builtin_stack('StrParam', 1, False)

    pcode('STARTTRANSLATION', CreateTranslation)
    pcode('TRANSLATIONRANGE1', TranslationRange, 4)
    pcode('TRANSLATIONRANGE2', TranslationRange, 8)
    pcode('ENDTRANSLATION', EndPrint, 'CreateTranslation')

    pcode('BEGINPRINT', BeginPrint)
    pcode('ENDPRINT', EndPrint, 'Print')
    pcode('ENDPRINTBOLD', EndPrint, 'PrintBold')
    pcode('ENDLOG', EndPrint, 'Log')
    pcode('MOREHUDMESSAGE', Instruction)
    pcode('OPTHUDMESSAGE', OptHudMessage)
    pcode('ENDHUDMESSAGE', HudMessage, 'HudMessage')
    pcode('ENDHUDMESSAGEBOLD', HudMessage, 'HudMessageBold')

    pcode('PRINTSTRING', PrintString, 's')
    pcode('PRINTNUMBER', PrintItem, 'd')
    pcode('PRINTCHARACTER', PrintItem, 'c')
    pcode('PRINTFIXED', PrintItem, 'f')
    pcode('PRINTLOCALIZED', PrintString, 'l')
    pcode('PRINTMAPCHARARRAY', PrintArray, MapVar)
    pcode('PRINTWORLDCHARARRAY', PrintArray, WorldVar)
    pcode('PRINTGLOBALCHARARRAY', PrintArray, GlobalVar)
    pcode('PRINTBIND', PrintString, 'k')
    pcode('PRINTBINARY', PrintItem, 'b')
    pcode('PRINTHEX', PrintItem, 'x')
    pcode('PRINTNAME', PrintItem, 'n')

    return pcodes


pcode_names = [
    'NOP', 'TERMINATE', 'SUSPEND',
    'PUSHNUMBER', 'LSPEC1', 'LSPEC2', 'LSPEC3',
    'LSPEC4', 'LSPEC5', 'LSPEC1DIRECT', 'LSPEC2DIRECT',
    'LSPEC3DIRECT', 'LSPEC4DIRECT', 'LSPEC5DIRECT', 'ADD',
    'SUBTRACT', 'MULTIPLY', 'DIVIDE', 'MODULUS', 'EQ',
    'NE', 'LT', 'GT', 'LE', 'GE',
    'ASSIGNSCRIPTVAR', 'ASSIGNMAPVAR', 'ASSIGNWORLDVAR',
    'PUSHSCRIPTVAR', 'PUSHMAPVAR', 'PUSHWORLDVAR',
    'ADDSCRIPTVAR', 'ADDMAPVAR', 'ADDWORLDVAR',
    'SUBSCRIPTVAR', 'SUBMAPVAR', 'SUBWORLDVAR',
    'MULSCRIPTVAR', 'MULMAPVAR', 'MULWORLDVAR',
    'DIVSCRIPTVAR', 'DIVMAPVAR', 'DIVWORLDVAR',
    'MODSCRIPTVAR', 'MODMAPVAR', 'MODWORLDVAR',
    'INCSCRIPTVAR', 'INCMAPVAR', 'INCWORLDVAR',
    'DECSCRIPTVAR', 'DECMAPVAR', 'DECWORLDVAR', 'GOTO',
    'IFGOTO', 'DROP', 'DELAY', 'DELAYDIRECT',
    'RANDOM', 'RANDOMDIRECT', 'THINGCOUNT',
    'THINGCOUNTDIRECT', 'TAGWAIT', 'TAGWAITDIRECT',
    'POLYWAIT', 'POLYWAITDIRECT', 'CHANGEFLOOR',
    'CHANGEFLOORDIRECT', 'CHANGECEILING',
    'CHANGECEILINGDIRECT', 'RESTART', 'ANDLOGICAL',
    'ORLOGICAL', 'ANDBITWISE', 'ORBITWISE', 'EORBITWISE',
    'NEGATELOGICAL', 'LSHIFT', 'RSHIFT', 'UNARYMINUS',
    'IFNOTGOTO', 'LINESIDE', 'SCRIPTWAIT',
    'SCRIPTWAITDIRECT', 'CLEARLINESPECIAL', 'CASEGOTO',
    'BEGINPRINT', 'ENDPRINT', 'PRINTSTRING',
    'PRINTNUMBER', 'PRINTCHARACTER', 'PLAYERCOUNT',
    'GAMETYPE', 'GAMESKILL', 'TIMER', 'SECTORSOUND',
    'AMBIENTSOUND', 'SOUNDSEQUENCE', 'SETLINETEXTURE',
    'SETLINEBLOCKING', 'SETLINESPECIAL', 'THINGSOUND',
    'ENDPRINTBOLD', 'ACTIVATORSOUND', 'LOCALAMBIENTSOUND',
    'SETLINEMONSTERBLOCKING', 'PLAYERBLUESKULL',
    'PLAYERREDSKULL', 'PLAYERYELLOWSKULL',
    'PLAYERMASTERSKULL', 'PLAYERBLUECARD', 'PLAYERREDCARD',
    'PLAYERYELLOWCARD', 'PLAYERMASTERCARD',
    'PLAYERBLACKSKULL', 'PLAYERSILVERSKULL',
    'PLAYERGOLDSKULL', 'PLAYERBLACKCARD', 'PLAYERSILVERCARD',
    'PLAYERONTEAM', 'PLAYERTEAM', 'PLAYERHEALTH',
    'PLAYERARMORPOINTS', 'PLAYERFRAGS', 'PLAYEREXPERT',
    'BLUETEAMCOUNT', 'REDTEAMCOUNT', 'BLUETEAMSCORE',
    'REDTEAMSCORE', 'ISONEFLAGCTF', 'LSPEC6',
    'LSPEC6DIRECT', 'PRINTNAME', 'MUSICCHANGE',
    'CONSOLECOMMANDDIRECT', 'CONSOLECOMMAND', 'SINGLEPLAYER',
    'FIXEDMUL', 'FIXEDDIV', 'SETGRAVITY',
    'SETGRAVITYDIRECT', 'SETAIRCONTROL',
    'SETAIRCONTROLDIRECT', 'CLEARINVENTORY', 'GIVEINVENTORY',
    'GIVEINVENTORYDIRECT', 'TAKEINVENTORY',
    'TAKEINVENTORYDIRECT', 'CHECKINVENTORY',
    'CHECKINVENTORYDIRECT', 'SPAWN', 'SPAWNDIRECT',
    'SPAWNSPOT', 'SPAWNSPOTDIRECT', 'SETMUSIC',
    'SETMUSICDIRECT', 'LOCALSETMUSIC', 'LOCALSETMUSICDIRECT',
    'PRINTFIXED', 'PRINTLOCALIZED', 'MOREHUDMESSAGE',
    'OPTHUDMESSAGE', 'ENDHUDMESSAGE', 'ENDHUDMESSAGEBOLD',
    'SETSTYLE', 'SETSTYLEDIRECT', 'SETFONT',
    'SETFONTDIRECT', 'PUSHBYTE', 'LSPEC1DIRECTB',
    'LSPEC2DIRECTB', 'LSPEC3DIRECTB', 'LSPEC4DIRECTB',
    'LSPEC5DIRECTB', 'DELAYDIRECTB', 'RANDOMDIRECTB',
    'PUSHBYTES', 'PUSH2BYTES', 'PUSH3BYTES', 'PUSH4BYTES',
    'PUSH5BYTES', 'SETTHINGSPECIAL', 'ASSIGNGLOBALVAR',
    'PUSHGLOBALVAR', 'ADDGLOBALVAR', 'SUBGLOBALVAR',
    'MULGLOBALVAR', 'DIVGLOBALVAR', 'MODGLOBALVAR',
    'INCGLOBALVAR', 'DECGLOBALVAR', 'FADETO', 'FADERANGE',
    'CANCELFADE', 'PLAYMOVIE', 'SETFLOORTRIGGER',
    'SETCEILINGTRIGGER', 'GETACTORX', 'GETACTORY',
    'GETACTORZ', 'STARTTRANSLATION', 'TRANSLATIONRANGE1',
    'TRANSLATIONRANGE2', 'ENDTRANSLATION', 'CALL',
    'CALLDISCARD', 'RETURNVOID', 'RETURNVAL',
    'PUSHMAPARRAY', 'ASSIGNMAPARRAY', 'ADDMAPARRAY',
    'SUBMAPARRAY', 'MULMAPARRAY', 'DIVMAPARRAY',
    'MODMAPARRAY', 'INCMAPARRAY', 'DECMAPARRAY', 'DUP',
    'SWAP', 'WRITETOINI', 'GETFROMINI', 'SIN', 'COS',
    'VECTORANGLE', 'CHECKWEAPON', 'SETWEAPON',
    'TAGSTRING', 'PUSHWORLDARRAY', 'ASSIGNWORLDARRAY',
    'ADDWORLDARRAY', 'SUBWORLDARRAY', 'MULWORLDARRAY',
    'DIVWORLDARRAY', 'MODWORLDARRAY', 'INCWORLDARRAY',
    'DECWORLDARRAY', 'PUSHGLOBALARRAY', 'ASSIGNGLOBALARRAY',
    'ADDGLOBALARRAY', 'SUBGLOBALARRAY', 'MULGLOBALARRAY',
    'DIVGLOBALARRAY', 'MODGLOBALARRAY', 'INCGLOBALARRAY',
    'DECGLOBALARRAY', 'SETMARINEWEAPON', 'SETACTORPROPERTY',
    'GETACTORPROPERTY', 'PLAYERNUMBER', 'ACTIVATORTID',
    'SETMARINESPRITE', 'GETSCREENWIDTH', 'GETSCREENHEIGHT',
    'THING_PROJECTILE2', 'STRLEN', 'SETHUDSIZE',
    'GETCVAR', 'CASEGOTOSORTED', 'SETRESULTVALUE',
    'GETLINEROWOFFSET', 'GETACTORFLOORZ', 'GETACTORANGLE',
    'GETSECTORFLOORZ', 'GETSECTORCEILINGZ', 'LSPEC5RESULT',
    'GETSIGILPIECES', 'GETLEVELINFO', 'CHANGESKY',
    'PLAYERINGAME', 'PLAYERISBOT', 'SETCAMERATOTEXTURE',
    'ENDLOG', 'GETAMMOCAPACITY', 'SETAMMOCAPACITY',
    'PRINTMAPCHARARRAY', 'PRINTWORLDCHARARRAY',
    'PRINTGLOBALCHARARRAY', 'SETACTORANGLE', 'GRABINPUT',
    'SETMOUSEPOINTER', 'MOVEMOUSEPOINTER', 'SPAWNPROJECTILE',
    'GETSECTORLIGHTLEVEL', 'GETACTORCEILINGZ',
    'SETACTORPOSITION', 'CLEARACTORINVENTORY',
    'GIVEACTORINVENTORY', 'TAKEACTORINVENTORY',
    'CHECKACTORINVENTORY', 'THINGCOUNTNAME',
    'SPAWNSPOTFACING', 'PLAYERCLASS', 'ANDSCRIPTVAR',
    'ANDMAPVAR', 'ANDWORLDVAR', 'ANDGLOBALVAR',
    'ANDMAPARRAY', 'ANDWORLDARRAY', 'ANDGLOBALARRAY',
    'EORSCRIPTVAR', 'EORMAPVAR', 'EORWORLDVAR',
    'EORGLOBALVAR', 'EORMAPARRAY', 'EORWORLDARRAY',
    'EORGLOBALARRAY', 'ORSCRIPTVAR', 'ORMAPVAR',
    'ORWORLDVAR', 'ORGLOBALVAR', 'ORMAPARRAY',
    'ORWORLDARRAY', 'ORGLOBALARRAY', 'LSSCRIPTVAR',
    'LSMAPVAR', 'LSWORLDVAR', 'LSGLOBALVAR', 'LSMAPARRAY',
    'LSWORLDARRAY', 'LSGLOBALARRAY', 'RSSCRIPTVAR',
    'RSMAPVAR', 'RSWORLDVAR', 'RSGLOBALVAR', 'RSMAPARRAY',
    'RSWORLDARRAY', 'RSGLOBALARRAY', 'GETPLAYERINFO',
    'CHANGELEVEL', 'SECTORDAMAGE', 'REPLACETEXTURES',
    'NEGATEBINARY', 'GETACTORPITCH', 'SETACTORPITCH',
    'PRINTBIND', 'SETACTORSTATE', 'THINGDAMAGE2',
    'USEINVENTORY', 'USEACTORINVENTORY',
    'CHECKACTORCEILINGTEXTURE', 'CHECKACTORFLOORTEXTURE',
    'GETACTORLIGHTLEVEL', 'SETMUGSHOTSTATE',
    'THINGCOUNTSECTOR', 'THINGCOUNTNAMESECTOR',
    'CHECKPLAYERCAMERA', 'MORPHACTOR', 'UNMORPHACTOR',
    'GETPLAYERINPUT', 'CLASSIFYACTOR', 'PRINTBINARY',
    'PRINTHEX','CALLFUNC','STRPARAM']

linespecials = [
    None, None, 'Polyobj_RotateLeft',
    'Polyobj_RotateRight', 'Polyobj_Move', None, 'Polyobj_MoveTimes8',
    'Polyobj_DoorSwing', 'Polyobj_DoorSlide', 'Line_Horizon',
    'Door_Close', 'Door_Open', 'Door_Raise', 'Door_LockedRaise',
    'Door_Animated', 'Autosave', None, 'Thing_Raise', 'StartConversation',
    'Thing_Stop', 'Floor_LowerByValue', 'Floor_LowerToLowest',
    'Floor_LowerToNearest', 'Floor_RaiseByValue', 'Floor_RaiseToHighest',
    'Floor_RaiseToNearest', 'Stairs_BuildDown', 'Stairs_BuildUp',
    'Floor_RaiseAndCrush', 'Pillar_Build', 'Pillar_Open',
    'Stairs_BuildDownSync', 'Stairs_BuildUpSync', 'ForceField',
    'ClearForceField', 'Floor_RaiseByValueTimes8',
    'Floor_LowerByValueTimes8', 'Floor_MoveToValue', 'Ceiling_Waggle',
    'Teleport_ZombieChanger', 'Ceiling_LowerByValue',
    'Ceiling_RaiseByValue', 'Ceiling_CrushAndRaise',
    'Ceiling_LowerAndCrush', 'Ceiling_CrushStop',
    'Ceiling_CrushRaiseAndStay', 'Floor_CrushStop', 'Ceiling_MoveToValue',
    None, 'GlassBreak', None, 'Sector_SetLink', 'Scroll_Wall',
    'Line_SetTextureOffset', 'Sector_ChangeFlags', None, None, None, None,
    None, 'Plat_PerpetualRaise', 'Plat_Stop', 'Plat_DownWaitUpStay',
    'Plat_DownByValue', 'Plat_UpWaitDownStay', 'Plat_UpByValue',
    'Floor_LowerInstant', 'Floor_RaiseInstant', 'Floor_MoveToValueTimes8',
    'Ceiling_MoveToValueTimes8', 'Teleport', 'Teleport_NoFog',
    'ThrustThing', 'DamageThing', 'Teleport_NewMap', 'Teleport_EndGame',
    'TeleportOther', 'TeleportGroup', 'TeleportInSector', None,
    'ACS_Execute', 'ACS_Suspend', 'ACS_Terminate', 'ACS_LockedExecute',
    'ACS_ExecuteWithResult', 'ACS_LockedExecuteDoor', None, None, None,
    None, 'Polyobj_OR_RotateLeft', 'Polyobj_OR_RotateRight',
    'Polyobj_OR_Move', 'Polyobj_OR_MoveTimes8', 'Pillar_BuildAndCrush',
    'FloorAndCeiling_LowerByValue', 'FloorAndCeiling_RaiseByValue', None,
    None, None, None, None, None, None, None, None, None, None, None,
    'Light_ForceLightning', 'Light_RaiseByValue', 'Light_LowerByValue',
    'Light_ChangeToValue', 'Light_Fade', 'Light_Glow', 'Light_Flicker',
    'Light_Strobe', 'Light_Stop', None, 'Thing_Damage', 'Radius_Quake',
    None, None, None, None, 'Thing_Move', None, 'Thing_SetSpecial',
    'ThrustThingZ', 'UsePuzzleItem', 'Thing_Activate', 'Thing_Deactivate',
    'Thing_Remove', 'Thing_Destroy', 'Thing_Projectile', 'Thing_Spawn',
    'Thing_ProjectileGravity', 'Thing_SpawnNoFog', 'Floor_Waggle',
    'Thing_SpawnFacing', 'Sector_ChangeSound', None, None, None, None,
    None, None, None, None, None, None, None, None, None,
    'Teleport_NoStop', None, None, None, 'FS_Execute',
    'Sector_SetPlaneReflection', 'Sector_Set3DFloor',
    'Sector_SetContents', None, None, None, None, None, None, None,
    'Generic_Crusher2', 'Sector_SetCeilingScale2',
    'Sector_SetFloorScale2', 'Plat_UpNearestWaitDownStay', 'NoiseAlert',
    'SendToCommunicator', 'Thing_ProjectileIntercept', 'Thing_ChangeTID',
    'Thing_Hate', 'Thing_ProjectileAimed', 'ChangeSkill',
    'Thing_SetTranslation', 'Plane_Align,', 'Line_Mirror',
    'Line_AlignCeiling', 'Line_AlignFloor', 'Sector_SetRotation',
    'Sector_SetCeilingPanning', 'Sector_SetFloorPanning',
    'Sector_SetCeilingScale', 'Sector_SetFloorScale', None,
    'SetPlayerProperty', 'Ceiling_LowerToHighestFloor',
    'Ceiling_LowerInstant', 'Ceiling_RaiseInstant',
    'Ceiling_CrushRaiseAndStayA', 'Ceiling_CrushAndRaiseA',
    'Ceiling_CrushAndRaiseSilentA', 'Ceiling_RaiseByValueTimes8',
    'Ceiling_LowerByValueTimes8', 'Generic_Floor', 'Generic_Ceiling',
    'Generic_Door', 'Generic_Lift', 'Generic_Stairs', 'Generic_Crusher',
    'Plat_DownWaitUpStayLip', 'Plat_PerpetualRaiseLip', 'TranslucentLine',
    'Transfer_Heights,', 'Transfer_FloorLight,', 'Transfer_CeilingLight,',
    'Sector_SetColor', 'Sector_SetFade', 'Sector_SetDamage',
    'Teleport_Line', 'Sector_SetGravity', 'Stairs_BuildUpDoom',
    'Sector_SetWind', 'Sector_SetFriction', 'Sector_SetCurrent',
    'Scroll_Texture_Both', 'Scroll_Texture_Model,', 'Scroll_Floor',
    'Scroll_Ceiling', 'Scroll_Texture_Offsets,', 'ACS_ExecuteAlways',
    'PointPush_SetForce,', 'Plat_RaiseAndStayTx0', 'Thing_SetGoal',
    'Plat_UpByValueStayTx', 'Plat_ToggleCeiling', 'Light_StrobeDoom',
    'Light_MinNeighbor', 'Light_MaxNeighbor', 'Floor_TransferTrigger',
    'Floor_TransferNumeric', 'ChangeCamera', 'Floor_RaiseToLowestCeiling',
    'Floor_RaiseByValueTxTy', 'Floor_RaiseByTexture',
    'Floor_LowerToLowestTxTy', 'Floor_LowerToHighest', 'Exit_Normal',
    'Exit_Secret', 'Elevator_RaiseToNearest', 'Elevator_MoveToFloor',
    'Elevator_LowerToNearest', 'HealThing', 'Door_CloseWaitOpen',
    'Floor_Donut', 'FloorAndCeiling_LowerRaise', 'Ceiling_RaiseToNearest',
    'Ceiling_LowerToLowest', 'Ceiling_LowerToFloor',
    'Ceiling_CrushRaiseAndStaySilA']

script_types = [

    "NORMAL",
    "OPEN",
    "RESPAWN",
    "DEATH",
    "ENTER",
    "PICKUP",
    "BLUE",
    "RED",
    "WHITE",
    None,
    None,
    None,
    "LIGHTNING",
    "UNLOADING",
    "DISCONNECT",
    "RETURN"
]

#Actors properties
#References:
# - for the index order: https://github.com/rheit/zdoom/blob/master/src/p_acs.cpp#L3615
# - for property type : https://zdoom.org/wiki/CheckActorProperty
aprop_names = [
    ('APROP_Health', False),
    ('APROP_Speed', False),
    ('APROP_Damage', False),
    ('APROP_Alpha', False),
    ('APROP_RenderStyle', False),
    ('APROP_SeeSound', True),
    ('APROP_AttackSound', True),
    ('APROP_PainSound', True),
    ('APROP_DeathSound', True),
    ('APROP_ActiveSound', True),
    ('APROP_Ambush', False),
    ('APROP_Invulnerable', False),
    ('APROP_JumpZ', False),
    ('APROP_ChaseGoal', False),
    ('APROP_Frightened', False),
    ('APROP_Gravity', False),
    ('APROP_Friendly', False),
    ('APROP_SpawnHealth', False),
    ('APROP_Dropped', False),
    ('APROP_Notarget', False),
    ('APROP_Species', True),
    ('APROP_NameTag', True),
    ('APROP_Score', False),
    ('APROP_Notrigger', False),
    ('APROP_DamageFactor', False),
    ('APROP_MasterTID', False),
    ('APROP_TargetTID', False),
    ('APROP_TracerTID', False),
    ('APROP_WaterLevel', False),
    ('APROP_ScaleX', False),
    ('APROP_ScaleY', False),
    ('APROP_Dormant', False),
    ('APROP_Mass', False),
    ('APROP_Accuracy', False),
    ('APROP_Dormant', False),
    ('APROP_Stamina', False),
    ('APROP_Height', False),
    ('APROP_Radius', False),
    ('APROP_ReactionTime', False),
    ('APROP_MeleeRange', False),
    ('APROP_ViewHeight', False),
    ('APROP_AttackZOffset', False),
    ('APROP_StencilColor', False),
    ('APROP_Friction', False),
    ('APROP_DamageMultiplier', False),
    ('APROP_MaxStepHeight', False),
    ('APROP_MaxDropOffHeight', False),
    ('APROP_DamageType', True),
]

pcode_index = {}
g = globals()
for i, n in enumerate(pcode_names):
    g['PCD_' + n] = i
    pcode_index[n] = i

pcodes = genpcodes()

del i, n, g

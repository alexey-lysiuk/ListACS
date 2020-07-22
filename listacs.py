#!/usr/bin/python

# listacs.py: ZDoom ACS disassembler/decompiler
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

import sys
import optparse

import acsutil
import doomwad


options = optparse.OptionParser(usage="usage: %prog [-d] [-s] [-v] [-c] [-o file] [-w wad] <file or lump>")
options.add_option("-o", "--output", action="store",
                   dest="output", metavar="FILE",
                   default=None, help="write output to FILE")

options.add_option("-d", "--decompile", action="store_true",
                   dest="decompile", metavar="BOOL",
                   default=False, help="try to decompile to ACS source")

options.add_option("-g", "--goto", action="store_true",
                   dest="goto", metavar="BOOL",
                   default=False, help="use 'goto' statement instead of switch-loop hack")

options.add_option("-s", "--strings", action="store_true",
                   dest="strings", metavar="BOOL",
                   default=False, help="print string table")

options.add_option("-v", "--vars", action="store_true",
                   dest="vars", metavar="BOOL",
                   default=False, help="print variable declarations when disassembling")

options.add_option("-c", "--comment", action="store_true",
                   dest="comment", metavar="BOOL",
                   default=False, help="comment out anything not executable")

options.add_option("-w", "--wad", action="store",
                   dest="wad", metavar="FILE",
                   default=None, help="read from a WAD file")


def indexes(lst):
    return sorted(b.index for b in lst)


def getstack(v, env):
    while v:
        yield v.tocode(env)
        v = v._next


class GotoParser(acsutil.Parser):
    spaces = '    '

    def __init__(self, scr, *args):
        acsutil.Parser.__init__(self, *args)
        self.script = scr
        self.stgt = self.read_instructions(scr.ptr)
        self.create_block(self.stgt)
        self.run()

    def goto_code(self, tgt):
        return 'goto block%d' % tgt.id

    def label_code(self, tgt):
        return ' block%s:' % tgt.id

    def prefix_code(self):
        yield '%s' % (self.script.getlabel())

    def suffix_code(self):
        yield ''

    def gen_code(self):
        addrs = self.targets.keys()
        sorted(addrs)
        self.blocks = blocks = []
        for i, a in enumerate(addrs):
            tgt = self.targets[a]
            if tgt.entries > 1:
                tgt.id = len(blocks) + 1
                blocks.append(tgt)

        yield self.script.getheader()
        yield '{'
        vars = ['local%d' % v for v in self.locals.vars if v >= self.script.argc]
        if vars:
            vars.sort()
            yield '    int %s;' % ', '.join(vars)

        for l in self.prefix_code():
            yield l

        self.stgt.id = 0

        for tgt in blocks:
            lbl = self.label_code(tgt)
            if lbl:
                yield lbl
            for l in tgt.block.genlines(self):
                yield self.spaces + l
            yield ''

        for l in self.suffix_code():
            yield l
        yield '}'


class SwitchParserScript(GotoParser):
    spaces = '        '

    def goto_code(self, tgt):
        return 'goto_block = %d; restart' % tgt.id

    def label_code(self, tgt):
        if len(self.blocks) != 1:
            return '    case %d:' % tgt.id

    def restart_code(self):
        if len(self.blocks) == 1:
            return 'restart'
        else:
            return 'goto_block = 0; restart'

    def prefix_code(self):
        if len(self.blocks) == 1:
            self.spaces = '    '
        else:
            yield '    int goto_block;'
            yield '    switch (goto_block) {'

    def suffix_code(self):
        if len(self.blocks) != 1:
            yield '    }'


class SwitchParserFunction(GotoParser):
    spaces = '            '

    def goto_code(self, tgt):
        return 'goto_block = %d; continue' % tgt.id

    def label_code(self, tgt):
        if len(self.blocks) != 1:
            return '        case %d:' % tgt.id

    def prefix_code(self):
        if len(self.blocks) == 1:
            self.spaces = '    '
        else:
            yield '    int goto_block;'
            yield '    while (1) {'
            yield '        switch (goto_block) {'

    def suffix_code(self):
        if len(self.blocks) != 1:
            yield '        }'
            yield '    }'

        if not self.script.isvoid:
            yield '    return 0;'


def declare_mapvars(acsf, seq):
    for var in seq:
        val = var.initval
        i = var.id
        isarray = not isinstance(val, int)
        isstring = var.is_string()
        if isarray:
            if isstring:
                yield 'int map%d[%d] = {%s};' % \
                    (i, len(val), ', '.join(acsf.getstring(v) for v in val))
            else:
                yield 'int map%d[%d] = {%s};' % \
                    (i, len(val), ', '.join(str(v) for v in val))
        else:
            if isstring:
                yield 'int map%d = %s; ' % (i, acsf.getstring(val))
            else:
                yield 'int map%d = %d;' % (i, val)
        if isarray:
            if not var.isarray:
                yield '// Warning: array map%d[] not used as array' % i
        else:
            if var.isarray:
                yield '// Warning: variable map%d used as array' % i


def declare_vars(seq, type):
    for var in seq:
        arrdec = ''
        if var.isarray:
            arrdec = '[]'
        yield '%s int %d:%s%d%s;' % (type, var.id, type, var.id, arrdec)


def getvars(acsf, type):
    vars = acsf.vars[type].vars
    varids = vars.keys()
    for id in sorted(varids):
        yield vars[id]


def main():
    opts, args = options.parse_args()
    if not args:
        options.print_help()
        return

    if opts.wad:
        f = open(opts.wad, 'rb')
        wad = doomwad.WadFile(f)
        f.close()

        dat = wad[args[0]].data
    else:
        dat = open(args[0], 'rb').read()

    acsf = acsutil.Behavior(dat)

    comment = ''
    if opts.comment:
        comment = '// '

    if opts.output:
        output = open(opts.output, 'w')
    else:
        output = sys.stdout

    if opts.strings:
        print('%sStrings:' % comment, file=output)
        for i, s in enumerate(acsf.strings):
            print('%s  %3d: %r' % (comment, i, s), file=output)
        print('', file=output)

    if opts.decompile:
        parsers = []
        for m in acsf.markers:
            if m.executable:
                if opts.goto:
                    p = GotoParser(m, acsf)
                elif isinstance(m, acsutil.Script):
                    p = SwitchParserScript(m, acsf)
                else:
                    p = SwitchParserFunction(m, acsf)
                parsers.append(p)

        print('#include "zcommon.acs"', file=output)
        print('', file=output)
        for l in declare_vars(getvars(acsf, 'global'), 'global'):
            print(l, file=output)

        for l in declare_vars(getvars(acsf, 'world'), 'world'):
            print(l, file=output)

        for l in declare_mapvars(acsf, getvars(acsf, 'map')):
            print(l, file=output)
        print('', file=output)

        for p in parsers:
            for l in p.gen_code():
                print(l, file=output)
    else:
        if opts.vars:
            for l in declare_mapvars(acsf, getvars(acsf, 'map')):
                print(l, file=output)
            print('', file=output)
        for m in acsf.markers:
            for lin in m.disassemble():
                print('%s%s' % (comment, lin), file=output)


if sys.hexversion < 0x3070000:
    print('This script requires Python 3.7 or newer')
    exit(1)

main()

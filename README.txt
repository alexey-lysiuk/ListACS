--- ZDoom ACS disassembler/decompiler ---

Requires Python version 2.5 or later: http://www.python.org

This is an ACS disassembler that supports ZDoom's ACS extensions. It
can also attempt to decompile scripts into ACS source code. 

-- Usage --

listacs [-d] [-s] [-v] [-c] [-o file] [-w wad] <file or lump>

Options:
  -h, --help            show this help message and exit
  -o FILE, --output=FILE
                        write output to FILE
  -d, --decompile       try to decompile to ACS source
  -g, --goto            use 'goto' statement instead of switch-loop hack
  -s, --strings         print string table
  -v, --vars            print variable declarations when disassembling
  -c, --comment         comment out anything not executable
  -w FILE, --wad=FILE   read from a WAD file **

** To read a lump from a specific map, use <map>/<lump>, e.g. 

   listacs -w wadfile.wad map01/behavior

-- Decompilation challenges --

The decompiler cannot currently detect loops, and so it has to use a
'goto' statement that ACC does not recognize. It can generate
compilable code by simulating 'goto' with a loop and a switch.

Another challenge is string detection. Since ACS refers to all strings
by an index into a string table, it's difficult to determine when a
value should be treated as a string or a number. Strings can be
reliably detected if they are passed directly to a built-in function
that takes a string argument. Variables that are passed to such
functions are marked so that any assignments to them also get treated
as strings.

As with any decompiler, variable names, function names, and comments
cannot be recovered.


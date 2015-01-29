from distutils.core import setup
import py2exe

setup(console=[{'script': 'listacs.py',
               'icon_resources': [(1, 'zdoom.ico')],
               'bundle-files': 1
                }],
      zipfile='python/library.zip')

import os
import sys
import imp
import tempfile
from pysmi.writer.base import AbstractWriter
from pysmi.compat import encode, decode
from pysmi import debug
from pysmi import error

class CFileWriter(AbstractWriter):
    def __init__(self, path):
        self._path = decode(os.path.normpath(path))

    def __str__(self): return '%s{"%s"}' % (self.__class__.__name__, self._path)

    def putData(self, mibname, data, comments=[],dryRun=False):
        mibname = mibname.replace('-','_')
        if dryRun:
            debug.logger & debug.flagWriter and debug.logger('dry run mode')
            return
        if not os.path.exists(self._path):
            try:
                os.makedirs(self._path)
            except OSError:
                raise error.PySmiWriterError('failure creating destination directory %s: %s' % (self._path, sys.exc_info()[1]), writer=self)
        if comments:
            data = '#\n' + ''.join(['#%s\n'% x for x in comments]) + '#\n' +data

        cfile = os.path.join(self._path,decode(mibname))+'.c'
        headerfile = os.path.join(self._path,decode(mibname))+'.h'

        try:
            fd, tfile = tempfile.mkstemp(dir =self._path)
            os.write(fd,encode(data))
            os.close(fd)
            if(os.path.isfile(cfile)):
                os.remove(cfile)
            os.rename(tfile,cfile)
        except (OSError, IOError, UnicodeEncodeError):
            exc = sys.exc_info()
            try:
                os.unlink(tfile)
            except OSError:
                pass
            raise error.PySmiWriterError('failure writing file %s: %s' % (cfile, exc[1]),file=cfile,write=self)

        debug.logger & debug.flagWriter and debug.logger('create file %s' % cfile)

        headerString = '#ifndef ' + mibname+ '_H\n'
        headerString += '#define ' + mibname + '_H\n'
        headerString += 'void register_'+mibname+'(void);\n'
        headerString += 'void unregister_'+mibname+'(void);\n'
        headerString += '#endif'

        try:
            fd, tfile = tempfile.mkstemp(dir=self._path)
            os.write(fd,encode(headerString))
            os.close(fd)
            if(os.path.isfile(headerfile)):
                os.remove(headerfile)
            os.rename(tfile, headerfile)
        except (OSError, IOError, UnicodeEncodeError):
            exc = sys.exc_info()
            try:
                os.unlink(tfile)
            except OSError:
                pass
            raise error.PySmiWriterError('failure writing file %s: %s' % (headerfile, exc[1]),file=cfile,write=self)
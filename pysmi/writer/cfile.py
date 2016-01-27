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

    def fileWrite(self, fileName, data, comments=[], dryRun=False):
        fileName = fileName.replace('-','_')
        if dryRun:
            debug.logger & debug.flagWriter and debug.logger('dry run mode')
            return
        if not os.path.exists(self._path):
            try:
                os.makedirs(self._path)
            except OSError:
                raise error.PySmiWriterError('failure creating destination directory %s: %s' % (self._path, sys.exc_info()[1]), writer=self)
        if comments:
            data = '//\n' + ''.join(['//%s\n'% x for x in comments]) + '//\n' + data
        fileName = os.path.join(self._path,decode(fileName))

        try:
            if 'custom.c' in fileName or 'custom.h' in fileName:
                return
            fd, tfile = tempfile.mkstemp(dir = self._path)
            os.write(fd, encode(data))
            os.close(fd)
            if(os.path.isfile(fileName)):
                os.remove(fileName)
            os.rename(tfile, fileName)
            fd, 
        except (OSError, IOError, UnicodeEncodeError):
            exc = sys.exc_info()
            try:
                os.unlink(tfile)
            except OSError:
                pass
            raise error.PySmiWriterError('failure writing file %s: %s' % (fileName, exc[1]),file=fileName,write=self)

    def putData(self, mibname, data, comments=[],dryRun=False):
        return
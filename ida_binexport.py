import idaapi
import idc

def windowsify(path):
    if path.startswith('/'):
        path = 'Z:\\\\' + path[1:]
    path = path.replace('/', '\\\\')
    return path

idc.auto_wait()
s = idc.Eval('BinExportBinary("%s")' % windowsify(idc.ARGV[1]))
idc.qexit(0)
#!/usr/bin/python
import os.path, sys, doctest

def splitpath(path):
    """Like os.path.split, only does all the splits at once."""
    l=[]
    while path:
        head,tail=os.path.split(path)
        l.insert(0, tail)
        path=head
    return l

def test(modulename):
    module=__import__(modulename, {}, {}, ['foo'])
    doctest.testmod(module)
    

def callback(basedir, dirname, filenames):
    r=[]
    for filename in filenames:
        if filename.startswith('.') \
           or filename=='SCCS' \
           or filename=='BitKeeper':
            continue
        r.append(filename)

        assert dirname[:len(basedir)]==basedir
        modulename='.'.join(splitpath(dirname[len(basedir)+1:]))
        if filename == '__init__.py':
            
            test(modulename)
        elif filename.endswith('.py'):
            modulename=modulename+'.'+filename[:-3]
            test(modulename)
    filenames[:]=r

sys.path.insert(0, 'lib')
dir=os.path.join(os.path.dirname(sys.argv[0]), '..', 'lib')
os.path.walk(dir, callback, dir)

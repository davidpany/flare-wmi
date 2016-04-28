#show_class_property_data.py
#Version 1.0
#
#Description:
#   prints timestamp, path, and data size for all class properties that contain data
#
#Use case:
#   Look for files, commands, output, etc. that is saved into WMI WMI class properties
#
#Usage:
#   env/bin/python flare-wmi/python-cim/samples/show_class_property_data.py win7 Repository_p/ > datadetails.xls
#
#Output:
#   prints output to stdout, recommend to redirect to xls file which will open in excel
#

import logging
import traceback

from cim import CIM
from cim import Index
from cim.objects import ObjectResolver
#from cim.formatters import dump_layout
from cim.objects import Tree
import inspect
import re

def rec_namespace(namespace,dataMO,o):
    #find all the paths we'd like to search for data
    for klass in namespace.classes:
        klassPath = (repr(klass)).split(":")
        try:
            #format the path so get_cd() can read it
            cd = o.get_cd(klassPath[0][1:],klassPath[1])
            
        except IndexError:
            #If the path doesn't have any data attributes, fugettaboutit
            continue
            
        #cd.tree() returns all the data for this class so we grep the data out of it and print it
        classTree = cd.tree()
        datas = re.findall(dataMO,classTree)
        counter = 1
        for hexdata in datas:
            print("{}\t{}:{}\t{}\t{}".format(cd.timestamp,klassPath[0][1:],klassPath[1],counter,len(hexdata)-8))
            counter += 1
        
    for ns in namespace.namespaces:
        rec_namespace(ns,dataMO,o)
    
def main(type_, path):
    print("Timestamp\tPath\tData#\tDataLength (nibbles)")
    if type_ not in ("xp", "win7"):
        raise RuntimeError("Invalid mapping type: {:s}".format(type_))

    c = CIM(type_, path)
    i = Index(c.cim_type, c.logical_index_store)
    o = ObjectResolver(c, i)

    c = CIM(type_, path)
    tree = Tree(c)
    
    #compiled here to save time
    dataMO = re.compile(" data\: [0-9a-fA-F]*")
    
    rec_namespace(tree.root,dataMO,o)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import sys
    main(*sys.argv[1:])

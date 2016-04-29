#show_classes_without_descriptions.py
#Version 1.0
#
#Description:
#   prints classes that don't have descriptions
#
#Use case:
#   Preliminary testing indicated that most legitimate classes had descriptions and attackers didnt
#   add descriptions to their classes. Further testing indicated that lots of legitimate classes 
#   don't have descriptions so this technique may not be valuable for anomaly detection. I didn't
#   want to waste the code though so it's here for archiving and testing.
#
#Usage:
#   env/bin/python flare-wmi/python-cim/samples/show_class_property_data.py win7 Repository_path/ 
#
#Output:
#   prints output to stdout, recommend to redirect to xls file which will open in excel
#

import logging
import traceback
from cim import CIM
from cim import Index
from cim.objects import ObjectResolver
from cim.objects import Tree
import inspect
import re

def rec_namespace(namespace,dataMO,o,AllocatedClassSet):
    #find all the paths we'd like to search for data
    for klass in namespace.classes:        
        AllocatedClassSet.add(repr(klass))
        
    for ns in namespace.namespaces:
        rec_namespace(ns,dataMO,o,AllocatedClassSet)
    
    return AllocatedClassSet
    
def CrossReferrenceDescriptions(AllocatedClassSet,path):
    DescriptionNullMO = re.compile(b"Description\x00\x00")
    ObjectsFile = open("{}OBJECTS.DATA".format(path),"rb")
    ObjectsLine = ObjectsFile.readline()
    DescriptionExistsSet = set()
    
    lineCounter = 1
    while ObjectsLine:
        ObjectsLineString = str(ObjectsLine)
        if "Description" in ObjectsLineString:
            if re.search(DescriptionNullMO,ObjectsLine):
                for AllocatedClass in AllocatedClassSet:
                    if AllocatedClass.split(":")[1] in ObjectsLineString:
                        strictMO = re.compile("{}\\\\x00\\\\x00Description".format(AllocatedClass.split(":")[1]))
                        if re.search(strictMO,str(ObjectsLineString)):
                            DescriptionExistsSet.add(AllocatedClass)
        ObjectsLine = ObjectsFile.readline()
    ObjectsFile.close()
    print("{}/{} exist".format(len(DescriptionExistsSet),len(AllocatedClassSet)))
    NoDescriptionSet = AllocatedClassSet.difference(DescriptionExistsSet)

    for ClassName in NoDescriptionSet:
        print(ClassName)
    
def main(type_, path):
    if type_ not in ("xp", "win7"):
        raise RuntimeError("Invalid mapping type: {:s}".format(type_))

    c = CIM(type_, path)
    i = Index(c.cim_type, c.logical_index_store)
    o = ObjectResolver(c, i)

    c = CIM(type_, path)
    tree = Tree(c)
    
    #compiled here to save time
    dataMO = re.compile(" data\: [0-9a-fA-F]*")
    
    BlankSet = set()
    AllocatedClassSet = rec_namespace(tree.root,dataMO,o,BlankSet)
    CrossReferrenceDescriptions(AllocatedClassSet,path)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import sys
    main(*sys.argv[1:])

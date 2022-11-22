import unittest
from z3 import *

I = DeclareSort("I")
S = StringSort()
Allow = Function("Allow", S, S, BoolSort())

Tuple = Datatype("tuple")
Tuple.declare('tuple', ('first', S), ('second', S))
Tuple = Tuple.create()
first = Tuple.first
second = Tuple.second

# Identity = Function("Identity",StringSort(),I)
T_allow = TransitiveClosure(Allow)

def generateAxioms(args):
    AllowedIdentityPairs = EmptySet(Tuple)
    # args : tuple of identities iams (strings)
    for (iam1, iam2) in args:
        AllowedIdentityPairs = SetAdd(AllowedIdentityPairs, Tuple.tuple(StringVal(iam1), StringVal(iam2)))
        AllowedIdentityPairs = SetAdd(AllowedIdentityPairs, Tuple.tuple(StringVal(iam1), StringVal(iam1)))
        AllowedIdentityPairs = SetAdd(AllowedIdentityPairs, Tuple.tuple(StringVal(iam2), StringVal(iam2)))        

    i1, i2 = Strings('i1 i2')
    return ForAll([i1, i2], Implies(Not(IsMember(Tuple.tuple(i1, i2), AllowedIdentityPairs)), Allow(i1, i2) == BoolVal(False)))

def generateChecks(args):
    # args : tuple of identities iams (strings)
    return [T_allow(StringVal(iam1),StringVal(iam2)) for iam1,iam2 in args]

def relation_check(args,check):
    s = Solver()
    s.add(generateAxioms(args))
    if s.check() == unsat:
        raise Exception("Invalid args")
    s.add(generateChecks(check))
    print(generateChecks(check))
    if s.check() == unsat:
        return False
    else:
        print(s.model())
        return True

class TransitivityChecker(unittest.TestCase):
    def test1(self):
        relations = [("role1","role2"),("role2","role3")]
        self.assertTrue(relation_check(relations,[("role1","role3")]))
        self.assertFalse(relation_check(relations, [("role2", "role1")]))
        self.assertFalse(relation_check(relations, [("role3", "role1")]))
        self.assertFalse(relation_check(relations, [("role3", "role2")]))
        
        self.assertTrue(relation_check(relations,[("role1","role1")]))
        self.assertTrue(relation_check(relations, [("role2", "role2")]))
        self.assertTrue(relation_check(relations, [("role3", "role3")]))

        self.assertFalse(relation_check(relations, [("role4", "role4")]))


    # def test2(self):
    #     self.assertFalse(transitivity_check([("role1","role2"),("role2","role3")],[("role3","role1")]))
    
    """
    Allow(Identity(StringVal("role1")),Identity(StringVal("role2")))
    Allow(Identity(StringVal("role2")),Identity(StringVal("role3")))    
    Allow(Identity(StringVal("role4")),Identity(StringVal("role4")))   

    query: 
    Not(T_allow(Identity(StringVal("role1")),Identity(StringVal("role3"))))
    """
    def test3(self):
        relations = [("role1","role2"),("role2","role3"), ("role4", "role4")]
        self.assertTrue(relation_check(relations, [("role1", "role3")]))
        self.assertFalse(relation_check(relations, [("role1", "role4")])) 
  
unittest.main()
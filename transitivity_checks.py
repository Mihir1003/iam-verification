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

    i1, i2 = Strings('i1 i2')
    return ForAll([i1, i2], Implies(Not(IsMember(AllowedIdentityPairs, Tuple.tuple(i1, i2))), T_allow(i1, i2) == BoolVal(False)))

def generateChecks(args):
    # args : tuple of identities iams (strings)
    return [Not(T_allow(StringVal(iam1),StringVal(iam2))) for iam1,iam2 in args]

def transitivity_check(args,check):
    s = Solver()
    s.add(generateAxioms(args))
    if s.check() == unsat:
        raise Exception("Invalid args")
    s.add(generateChecks(check))
    if s.check() == unsat:
        return True
    else:
        print(s.model())
        return False

class TransitivityChecker(unittest.TestCase):

    def test1(self):
        self.assertTrue(transitivity_check([("role1","role2"),("role2","role3")],[("role1","role3")]))
    
    def test2(self):
        self.assertFalse(transitivity_check([("role1","role2"),("role2","role3")],[("role3","role1")]))
    
    """
    Allow(Identity(StringVal("role1")),Identity(StringVal("role2")))
    Allow(Identity(StringVal("role2")),Identity(StringVal("role3")))    
    Allow(Identity(StringVal("role4")),Identity(StringVal("role4")))   

    query: 
    Not(T_allow(Identity(StringVal("role1")),Identity(StringVal("role3"))))
    """
    def test3(self):
        self.assertFalse(transitivity_check([("role1","role2"),("role2","role3"), ("role4", "role4")],
                                                [("role1", "role3")]))

  
unittest.main()
from z3 import *
import unittest

I = DeclareSort("I")
P = DeclareSort("P")
Policy = Function("Policy",BoolSort(),I,P,BoolSort())

AsPrincipal = Function("AsPrinciple",I,P,BoolSort())

Identity = Function("Identity",StringSort(),I)
Principal = Function("Principal",StringSort(),P)
Allowed = Function("Allow", I, P, BoolSort())
Allow = Function("Allow", I, I, BoolSort())
tc_allow = TransitiveClosure(Allow)
role1,role2,role3,role4 = map(lambda x :  StringVal(x),["role1","role2", "role3", "role4"])
true = BoolVal(True)
false = BoolVal(False)


def DeclareIdentity(string):
    return Policy(true,Identity(string),Principal(string))

i1,i2 = Strings("i1 i2")
p1,p2 = Strings("p1 p2")
print(i1,i2)

axioms =[
     ForAll([i1,p1],Implies(i1==p1,AsPrincipal(Identity(i1),Principal(p1)))),
    ForAll([i1,p1],Implies(
            And(Policy(BoolVal(True),Identity(i1),Principal(p1))),
            # AsPrincipal(Identity(i1),Principal(p1))),
        Allowed(Identity(i1),Principal(p1)))),
    ForAll([i1,p1,i2],Implies(And(
        AsPrincipal(Identity(i1),Principal(p1)),
        Allowed(Identity(i2),Principal(p1))),
        Allow(Identity(i2),Identity(i1))))]

class TransitivityChecker(unittest.TestCase):
    def test_3elems(self):
        solver = Solver()
        solver.add(axioms)
        constraints = [
            Policy(true,Identity(role1),Principal(role2)),
            Policy(true,Identity(role2),Principal(role3)),
            Policy(true,Identity(role3),Principal(role3)),
            ]
        solver.add(constraints)
        checks = [
            # Not(Allow(Identity(role1),Identity(role2))),
            # Allow(Identity(role2),Identity(role3)),
            Not(tc_allow(Identity(role1),Identity(role3)))]
        solver.add(checks)

        if solver.check() == unsat:
            self.assertTrue(True)
        else:
            print(solver.model())
            self.assertTrue(False)
        # self.assertEqual(solver.check(),unsat)
        # print(solver.model())
        # self.fail()


    def test_4elems(self):
        solver = Solver()
        solver.add(axioms)
        constraints = [
            # Policy(true,Identity(role1),Principal(role2)),
            # Policy(true,Identity(role2),Principal(role3)),
            # Policy(true,Identity(role3),Principal(role3)),
            # DeclareIdentity(role3),


            # Policy(true,Identity(role3),Principal(role4)),
            # DeclareIdentity(role4),

            Allow(Identity(role1),Identity(role2)),
            Allow(Identity(role2),Identity(role3)),
            Allow(Identity(role3),Identity(role3)),
            Allow(Identity(role4),Identity(role4))
            
            ]
        solver.add(constraints)
        checks= [Not(tc_allow(Identity(role1),Identity(role3)))]
        solver.add(checks)
        self.assertEqual(solver.check(),unsat)


unittest.main()


# constraints = [
#     Policy(true,Identity(role1),Principal(role2)),
#     Policy(true,Identity(role2),Principal(role3)),
#     Policy(true,Identity(role3),Principal(role3)),
#     DeclareIdentity(role3),


#     Policy(true,Identity(role3),Principal(role4)),
#     DeclareIdentity(role4),

#     Allow(Identity(role1),Identity(role2)),
#     Allow(Identity(role2),Identity(role3)),
#     Allow(Identity(role3),Identity(role3)),
#     Allow(Identity(role4),Identity(role4))
# ]

    # Policy(true,Identity(role4),Principal(role4)),
    # DeclareIdentity(role4),
    # DeclareIdentity(role3),


# s = Solver()
# s.add(axioms)
# s.add(constraints)
# print(s.check())
# s.add(Not(Allowed(Identity(role1),Principal(role2))))
# s.add(Not(AsPrincipal(Identity(role1),Principal(role2))))
# s.add(Not(Allowed(Identity(role4),Principal(role4))))
# s.add(Not(tc_allow(Identity(role1),Identity(role3))))
# if s.check() == unsat:
#     print("authorized")
# else:
#     print("unauthourized")
#     print(s.model())
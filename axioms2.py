from z3 import *


I = DeclareSort("I")
P = DeclareSort("P")
Policy = Function("Policy",BoolSort(),I,P,BoolSort())

AsPrincipal = Function("AsPrinciple",I,P,BoolSort())

DeclareIdentity = Function("DeclareIdentity",I,BoolSort())
Identity = Function("Identity",StringSort(),I)
Principal = Function("Principal",StringSort(),P)
Allowed = Function("Allow", I, P, BoolSort())
Allow = Function("Allow", I, I, BoolSort())
tc_allow = TransitiveClosure(Allow)
role1,role2,role3,role4 = map(lambda x :  StringVal(x),["role1","role2", "role3", "role4"])

# def asPrinciple() :


# i1,i2 = Consts("i1 i2",I)
# p1,p2 = Consts("p1 p2",P)
# print(p1.,p2)

i1,i2 = Strings("i1 i2")
p1,p2 = Strings("p1 p2")
print(i1,i2)
true = BoolVal(True)
false = BoolVal(False)
axioms =[
     ForAll([i1,p1],Implies(i1==p1,AsPrincipal(Identity(i1),Principal(p1)))),
    ForAll([i1,p1],Implies(
            And(Policy(BoolVal(True),Identity(i1),Principal(p1))),
            # AsPrincipal(Identity(i1),Principal(p1))),
        Allowed(Identity(i1),Principal(p1)))),
    ForAll([i1,p1,i2],Implies(And(
        AsPrincipal(Identity(i1),Principal(p1)),
        Allowed(Identity(i2),Principal(p1))),
        Allow(Identity(i2),Identity(i1)))),
    Policy(true,Identity(role1),Principal(role2)),
    Policy(true,Identity(role2),Principal(role3)),
    Policy(true,Identity(role3),Principal(role3)),

    # DeclareIdentity(Identity(role4))
    # DeclareIdentity(Identity(role3))
]

s = Solver()
s.add(axioms)
print(s.check())
# s.add(Not(Allowed(Identity(role1),Principal(role2))))
# s.add(Not(AsPrincipal(Identity(role1),Principal(role2))))
s.add(Not(tc_allow(Identity(role1),Identity(role3))))
if s.check() == unsat:
    print("authorized")
else:
    print("unauthourized")
    print(s.model())
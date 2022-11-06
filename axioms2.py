from z3 import *

I = DeclareSort("I")
P = DeclareSort("P")
Policy = Function("Policy",BoolSort(),I,I,BoolSort())


Allow = Function("Allow", I, I, BoolSort())
tc_allow = TransitiveClosure(Allow)
role1,role2,role3,role4 = Consts("role1 role2 role3 role4",I)
i1,i2 = Consts("i1 i2",I)
true = BoolVal(True)
false = BoolVal(False)
axioms =[
    # ForAll([i1,i2],Allow(i1,i2)==BoolVal(False)),
    ForAll([i1,i2],Implies(Policy(BoolVal(True),i1,i2),Allow(i1,i2))),
# ForAll([i1,i2],Implies(Policy(BoolVal(False),i1,i2),Allow(i1,i2)==BoolVal(False))),
# ForAll([i1,i2],If(Policy(true,i1,i2),Allow(i1,i2)==BoolVal(True),Allow(i1,i2)==BoolVal(False))),
# Policy(BoolVal(True),role2,role1),
# Policy(BoolVal(True),role1,role3),
# Policy(BoolVal(True),role3,role4)
Policy(true,role1,role2),
Policy(true,role2,role3)
]

s = Solver()
s.add(axioms)
print(s.check())
s.add(Not(tc_allow(role1,role2)))
print(s.check())
# print(s.model())
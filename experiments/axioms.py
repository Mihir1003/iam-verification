import z3
'''
Setting up base axioms:
Text:
Identity include Users, Groups, Roles
Identity owns policies
Roles can assume other roles if a policy allows
Policy gives access to actions on identities and resources
Groups are made of multiple users

Resources can also own policies
Policies give access to principals
Principals describe identities and resources
Every identity has an associated IAM string

Policy Evaluation:
- Decision  starts with deny
- Explicit deny -> Deny
- is principal part of organization SCP (future)
- Is there a resource based policy on requested resoruce
    - Allow?
        - read here: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- Does the principle have identity based policy:
    - yes
        -Allow
            - Permidssion boundry?
                -Allow?
                [Session principles in  the future]
'''



PrincipalSort = z3.StringSort()

Policy = z3.Datatype("Policy")
Policy.declare("Policy",("Effect", z3.BoolSort()), ("Principle", PrincipalSort))
Policy.declare("Nothing")

Role = z3.Datatype("Role")
Role.declare("Role",("policy",Policy), ("iam", z3.StringSort()))

Policy, Role = z3.CreateDatatypes(Policy,Role)

# Allow
Allow = z3.Function('allow', Role, Role, z3.BoolSort())

# User = z3.Datatype("User")
# User.declare("User",("policies",PoliciesSort))
# User = User.create()

p = z3.Const('p', Policy)
i = z3.Const('i', Role)
#check_policy = z3.Lambda([p,i], z3.And(Policy.Effect(p), Role.iam(i) == Policy.Principle(p)))

def check_policy(p, i):
	return z3.And(Policy.Effect(p), Role.iam(i) == Policy.Principle(p))

def checkUser(role, identity):
    return check_policy(Role.policy(role), identity)
	# return z3.And(Policy.Effect(p), Role.iam(i) == Policy.Principle(p))

test_policy = Policy.Policy(z3.BoolVal(True), z3.StringVal("C"))
test_role = Role.Role(test_policy, z3.StringVal("B"))
access_role1 = Role.Role(
				Policy.Policy(z3.BoolVal(True), z3.StringVal("D")), 
				z3.StringVal("C"))
access_role2 = Role.Role(Policy.Nothing, z3.StringVal("D"))

r1 = z3.Const('r1', Role)
r2 = z3.Const('r2', Role)
r3 = z3.Const('r3', Role)
# allowsImplication = z3.ForAll([r1, r2], z3.Implies(checkUser(r1, r2), Allow(r1, r2)))
# transitivity = z3.ForAll([r1, r2, r3], z3.Implies(z3.And(Allow(r1, r2), Allow(r2, r3)), Allow(r1, r3)))
# TC_Allow = z3.TransitiveClosure(Allow)
s = z3.Solver()
# s.add(allowsImplication)
# s.add(transitivity)
# s.add(z3.Implies(z3.ForAll([r1,r2],z3.And(Policy.Effect(Role.policy(r1)), Role.iam(r2) == Policy.Principle(Role.policy(r1)))),Allow(r1,r2)))
# s.add(z3.And(r1 == access_role1, r2 == test_role, r3 == access_role2)) 
# s.add(checkUser(r1, r2))
# s.add(checkUser(r1, r3))
# print(checkUser(test_role,access_role1))
# s.add(r1!= r2)
# s.add(checkUser(test_role,access_role2))
s.add(checkUser(test_role,access_role1))
if s.check() == z3.sat:
	print(s.model())
else:
	print('unsat')
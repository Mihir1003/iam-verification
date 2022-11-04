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

PrincipleSort = z3.DeclareSort("Principle")



Role = z3.Datatype("Role")
Policy = z3.Datatype("Policy")
Policy.declare("Policy",("Effect", z3.BoolSort()),("Principle", Role))

Role.declare("Role",("policies",Policy))

Policy, Role = z3.CreateDatatypes(Policy,Role)


IdentitySort = z3.DeclareSort("Identity")
Allow = z3.Function('allow',IdentitySort,IdentitySort,z3.BoolSort())





User = z3.Datatype("User")
User.declare("User",("policies",PoliciesSort))
User = User.create()

p = Policy
i = IdentitySort
# check_policy = z3.Lambda([p,i],z3.And(Policy.Effect(p),i==Policy.Principle(p)))

# def checkUser(user,identity):
#     return z3.Exists(i,check_policy(User.polcies(user)[i],identity))


pols = z3.Array('pols',z3.IntSort(),Policy)
a = Role.Role(pols)
p = Policy.Policy(z3.BoolVal(True),a)
pols[0] = p
b = Role.Role(pols)
solver = z3.Solver()
# solver.add(checkUser(b,a))
solver.add(Policy.Effect(z3.Select(pols,0)))
assert solver.check() == z3.sat






from pickle import EMPTY_SET
import z3

ActionS3Type = z3.Datatype('Action')
ActionS3Type.declare('ListBucket')
ActionS3 = ActionS3Type.create()

PrincipalType = z3.Datatype('Principal')
PrincipalType.declare('role', ('names', z3.SetSort(z3.StringSort())))
PrincipalType.declare('account', ('account_names', z3.SetSort(z3.StringSort())))
PrincipalType.declare('service', ('service_names', z3.SetSort(z3.StringSort())))
Principal = PrincipalType.create()

ResourceType = z3.Datatype('Resource')
ResourceType.declare('resource', ('names', z3.SetSort(z3.StringSort())))
Resource = ResourceType.create()
"""
{
	"Name": "RoleA",
	"Policies": [{
	"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"Principal": {"Role": "RoleB"},
			"Action": "sts:AssumeRole"
		}
	},
	{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"Action": "s3:ListBucket",
			"Resource": "arn:aws:s3:::example_bucket"
		}
	}]
}"""

# A general purpose match combinator
def match(x, **kwargs):
	t = x.sort()
	nc = t.num_constructors()
	acc = kwargs["_"] # default argument
	for c in range(nc):
		con = t.constructor(c)
		print(con.name() in kwargs)
		rec = t.recognizer(c)
		nfields = con.arity()
		if con.name() in kwargs:
			if nfields == 0:
				res = kwargs[con.name()]
			else:
				res = kwargs[con.name()](  *[t.accessor(c,a)(x) for a in range(nfields)] )
			acc = z3.If(rec(x), res, acc)
	return acc

def principal_match(principal1, principal2):
	return match(
		principal1,
		role = lambda names1: match(principal2, 
										role = lambda names2: 
											z3.Not(z3.SetIntersect(names1, names2) == z3.EmptySet(z3.StringSort())),
										_ = z3.BoolVal(False)),

		account = lambda account_names1: match(principal2, 
										account = lambda account_names2: 
											z3.Not(z3.SetIntersect(account_names1, account_names2) == z3.EmptySet(z3.StringSort())),
										_ = z3.BoolVal(False)),
		service = lambda service_names1: match(principal2, 
											service = lambda service_names2: 
											z3.Not(z3.SetIntersect(service_names1, service_names2) == z3.EmptySet(z3.StringSort())),
										_ = z3.BoolVal(False)),
		_ = z3.BoolVal(False)
	)

def create_set(items, sort):
	s = z3.EmptySet(sort)
	for item in items:
		s = z3.SetAdd(s, item)
	return s


def role_principal(roles=[]):
	role_set = z3.EmptySet(z3.StringSort())
	for role in roles:
		role_set = z3.SetAdd(role_set, z3.StringVal(role))
	return Principal.role()

pr =  Principal.role(z3.SetAdd(z3.EmptySet(z3.StringSort()), z3.StringVal("RoleB")))
print(pr)

pr1 = z3.Var(0, Principal)
access = z3.Function('access', Principal, ActionS3, Resource, z3.BoolSort())
#print(principal_match(pr1, prConst))

#print(z3.Implies(principal_match(pr, prConst), 
	#access(pr1, ActionS3.ListBucket, Resource.resource(create_set(["arn:aws:s3:::example_bucket"], z3.StringVal, z3.StringSort()))) == z3.BoolVal(True)))

assumes = z3.Function('assumes', Principal, Principal, z3.BoolSort())


# reflexive_rule = z3.ForAll([pr1], assumes(pr1, pr1) == z3.BoolVal(True))
# transitive_rule = z3.ForAll([pr1, pr2, pr3], 
# 						z3.Implies(
# 							z3.And(assumes(pr1, pr2), assumes(pr2, pr3)), 
# 								assumes(pr1, pr3)))
TC_R = z3.TransitiveClosure(assumes)

def account_principal(name):
	return Principal.account(create_set([z3.StringVal(name)], z3.StringSort()))

def role_principal(role):
	return Principal.role(create_set([z3.StringVal(role)], z3.StringSort()))

p1 = account_principal("bob")
p2 = role_principal("RoleA")
p3 = account_principal("RoleB")

pr1 = z3.Const('pr1', Principal)
pr2 = z3.Const('pr1', Principal)

seen_principals = [p1, p2, p3]
print(seen_principals)

slv = z3.Solver()
#slv.add(transitive_rule)
cond_pr1 = z3.BoolVal(True)
cond_pr2 = z3.BoolVal(True)
for pr in seen_principals:
	cond_pr1 = z3.Or(principal_match(pr1, pr), cond_pr1)
	cond_pr2 = z3.Or(principal_match(pr2, pr), cond_pr1)
exclusive = z3.Implies(z3.Or(z3.Not(cond_pr1), z3.Not(cond_pr2)), z3.Not(assumes(pr1, pr2)))

slv.add(exclusive)

# slv.add(TC_R(p1, p4))


#if slv.check() == z3.sat:
#	print(z3.sat)
#	print(slv.model())



#pr2 = z3.Var(1, Principal)
#pr3 = z3.Var(2, Principal)
#act = z3.Var(3, ActionS3)
#res = z3.Var(4, Resource)

#z3.ForAll([pr2, pr3, act, res], z3.Implies(assumes(pr2, pr3), access(pr2, act, res)

#access(pr1, ActionS3.ListBucket, ))

# ... and more


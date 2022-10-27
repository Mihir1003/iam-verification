
from cgi import print_arguments
from typing import Set
import z3

policy1 = {
	'Effect': 'Allow',
	'Principal': 'user',
	'Action': 'getObject',
	'Resource': 'protected/resource1.prot'
}

a1 = z3.String('a1')
p1 = z3.String('p1')
r1 = z3.String('r1')

constraints = z3.And(
		a1 == z3.StringVal("getObject"),
		p1 == z3.StringVal("user"),
		r1 == z3.StringVal("protected/resource1.prot"))
s = z3.Solver()
s.add(constraints)

# check if Principal 'user' can access protected/resource1.prot, i.e.,
# given our constraints, can it be the case that access == "getObject" and principal = "user"? (the answer is yes)
query = z3.And(a1 == z3.StringVal("getObject")), p1 == z3.StringVal('user')
s.add(query)
assert s.check() == z3.sat

s = z3.Solver()
s.add(constraints)
# check if principal "bob" can access protected/resource1.prot 
# The answer is no, because we already have the assumption that p1 = "user"
# (p1 = "user" and p1 = "bob") is always unsat since a string cannot equal two distinct values at once
query = z3.And(a1 == z3.StringVal("getObject"), p1 == z3.StringVal("bob"))
s.add(query)
assert s.check() == z3.unsat

policy2 = {
	'Effect': 'allow',
	'Principal': 'admin',
	'Action': 'getObject',
	'Resource': [
		'protected/resource1.prot'
		'protected/secret.prot'
	]
}

a2 = z3.String('a2')
p2 = z3.String('p2')
r2 = z3.String('r2')
s = z3.Solver()

resources = z3.SetAdd(z3.SetAdd(z3.EmptySet(z3.StringSort()), z3.StringVal('protected/secret.prot')),
							z3.StringVal('protected/resource1.prot'))

s.add(z3.And(a2 == z3.StringVal("getObject"), p2 == z3.StringVal("admin"),
				z3.IsMember(r2, resources)))

# can principal admin access resource 'protected/secret.prot'?, i.e.,
# can we have principal == admin and (secret.prot in resources) ? 
query = z3.And(p2 == z3.StringVal("admin"),r2 == z3.StringVal('protected/secret.prot'))
s.add(query)
assert s.check() == z3.sat



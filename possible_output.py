from z3 import Function, BoolSort, StringSort, Strings, Bool, InRe, Re, And, Implies, ForAll, BoolVal, \
     StringVal, Solver, Lambda, If, Int, IntVal, sat, unsat, Or, TransitiveClosure

from id_match import iam_pattern_to_regex

# def f(a):
#     return a < IntVal(10)

# s = Solver()
# x = Int('x')
# s.add(f(x))
# s.check()
# print(s.model())
# u, a, r = Strings('u a r')
# e = Bool('e')
# Policy = Lambda([e, u, a, r], 
#    

"""
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": false,
        "CreateDate": "2015-02-06T18:40:58+00:00"
    }
}
"""

def Policy(e, u, a, r):
    return Or(And(u == StringVal("arn:aws:iam::218925562655:user/test1"), 
                InRe(a, iam_pattern_to_regex("sts:*")),
                InRe(r, iam_pattern_to_regex("arn:aws:iam::218925562655:role/testrole*")),
                e == BoolVal(True)),

               And(u == StringVal("arn:aws:iam::218925562655:role/testrole2"),
                    InRe(a, iam_pattern_to_regex("s3:*")),
                    InRe(r, iam_pattern_to_regex("*")))
    )

def Access(u1, u2):
    return Or(u1 == u2, 
            And(AllowsUser(u1, u2),
                 Policy(BoolVal(True), u1, StringVal("sts:AssumeRole"), u2)))

"""
"AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Statement1",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::218925562655:user/test2",
                            "arn:aws:iam::218925562655:user/test1",
                            "arn:aws:iam::218925562655:user/test3"
                        ]
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
"""

"""
"AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Statement1",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::218925562655:role/testrole1",
                            "arn:aws:sts::218925562655:assumed-role/testrole1/testrolesession"
                        ]
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
"""

def AllowsUser(id, role):
    return Or(
                And(role == StringVal("arn:aws:iam::218925562655:role/testrole1"), 
                    Or(InRe(id, iam_pattern_to_regex("arn:aws:iam::218925562655:user/test2")),
                        InRe(id, iam_pattern_to_regex("arn:aws:iam::218925562655:user/test1")),
                        InRe(id, iam_pattern_to_regex("arn:aws:iam::218925562655:user/test3")))),
                
                And(role == StringVal("arn:aws:iam::218925562655:role/testrole2"), 
                    Or(InRe(id, iam_pattern_to_regex("arn:aws:iam::218925562655:role/testrole1")),
                        InRe(id, iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole1/testrolesession"))))
    )

s = Solver()
# s.add()
s.add(Policy(BoolVal(True), StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("sts:Assume"),
                StringVal("arn:aws:iam::218925562655:role/testrole1")))

if s.check() == sat:
    print(s.model())
else:
    print('1 unsat')

s = Solver()
s.add(Access(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("arn:aws:iam::218925562655:user/test1")))
if s.check() == sat:
    print(s.model())
else:
    print('2 unsat')

s = Solver()
s.add(Access(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("arn:aws:iam::218925562655:role/testrole1")))
if s.check() == sat:
    print(s.model())
else:
    print('3 unsat')

tc_allow = TransitiveClosure(Access)

s.add(Access(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("arn:aws:iam::218925562655:role/testrole2")))
if s.check() == sat:
    print(s.model())
else:
    print('4 unsat')



from z3 import BoolSort, StringSort, Strings, InRe, And, BoolVal, \
     StringVal, Or, TransitiveClosure, RecAddDefinition, RecFunction, String,\
     SetAdd, EmptySet, IsMember, Array, Store, Select, simplify, Contains, Solver, sat,\
     Intersect, FreshConst, ReSort, Re, Distinct, If

from id_match import iam_pattern_to_regex
from functools import reduce

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
def z3_array(name, ksort, vsort, kvs):
    #xprint(list(kvs.items()))
    return reduce(lambda arr, kv: Store(arr, kv[0], kv[1]), kvs.items(), Array(name, ksort, vsort))

def SessionString(u):
    return If(u == StringVal("arn:aws:iam::218925562655:role/testrole1"),
        iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole1/*"),
        If(
            u == StringVal("arn:aws:iam::218925562655:role/testrole2"),
            iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole2/*"),
            Re(u)
        )
    )

# SessionString = z3_array('SessionString', StringSort(), ReSort(StringSort()),
#             {
#                 StringVal("arn:aws:iam::218925562655:role/testrole1"): iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole1/*"),
#                 StringVal("arn:aws:iam::218925562655:role/testrole2"): iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole2/*"),
#             })

def Policy(e, u, a, r):
    return Or(And(u == StringVal("arn:aws:iam::218925562655:user/test1"), 
                InRe(a, iam_pattern_to_regex("sts:*")),
                InRe(r, iam_pattern_to_regex("arn:aws:iam::218925562655:role/testrole*")),
                e == BoolVal(True)),

                And(u == StringVal("arn:aws:iam::218925562655:role/testrole1"), 
                    InRe(a, iam_pattern_to_regex("sts:*")),
                    InRe(r, iam_pattern_to_regex("arn:aws:iam::218925562655:role/testrole*")),
                    e == BoolVal(True)),

               And(u == StringVal("arn:aws:iam::218925562655:role/testrole2"),
                    InRe(a, iam_pattern_to_regex("s3:GetObject")),
                    InRe(r, iam_pattern_to_regex("*")))
    )

def z3_set(sort, *ts):
    return reduce(SetAdd, ts, EmptySet(sort))

RoleSet = z3_set(StringSort(), StringVal("arn:aws:iam::218925562655:role/testrole1"),
                               StringVal("arn:aws:iam::218925562655:role/testrole2"))

def IsRole(u):
    return IsMember(u, RoleSet)

def NonEmptyRegexIntersect(re1, re2):
    return Distinct(Intersect(re1, re2), Re(''))

def AllowsIdentity(id, role):
    print(f"id: {id}; role: {role}")
    return Or(
                And(role == StringVal("arn:aws:iam::218925562655:role/testrole1"), 
                    Or(InRe(id, iam_pattern_to_regex("arn:aws:iam::218925562655:user/test2")),
                        InRe(id, iam_pattern_to_regex("arn:aws:iam::218925562655:user/test1")),
                        InRe(id, iam_pattern_to_regex("arn:aws:iam::218925562655:user/test3")))),
                
                And(role == StringVal("arn:aws:iam::218925562655:role/testrole2"), 
                    Or(InRe(id, iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole1/testrolesession")),
                        And(IsRole(id), NonEmptyRegexIntersect(iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole2/testrolesession"), 
                            SessionString(id))))))
                                                
Access = RecFunction('Access', StringSort(), StringSort(), BoolSort())
u1, u2 = Strings('u1 u2')
RecAddDefinition(Access, [u1, u2], 
    Or(u1 == u2, 
            And(
                 AllowsIdentity(u1, u2),
                 Policy(BoolVal(True), u1, StringVal("sts:AssumeRole"), u2)))
)

TC_Access = TransitiveClosure(Access)

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

def NonEmptyIntersection(re1, re2):
    return InRe(FreshConst(StringSort()), Intersect(re1, re2))


q = String('q')
def Allow(u, a, r):
    return And(TC_Access(u, q), 
        Policy(BoolVal(True), q, a, r))

# s = Solver()
# s.add(NonEmptyIntersection(iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole1/*"),
#                            iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole1/testrolesession")))
# if s.check() == sat:
#     print(s.model())
# else:
#     print('unsat')

# s = Solver()
# s.add(And(IsRole(StringVal("arn:aws:iam::218925562655:role/testrole1")), NonEmptyRegexIntersect(Select(SessionString, StringVal("arn:aws:iam::218925562655:role/testrole1")), 
#                                             iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole1/testrolesession"))))
# if s.check() == sat:
#     print(s.model())
# else:
#     print('unsat 1')

# s = Solver()
# s.add(AllowsIdentity(StringVal("arn:aws:iam::218925562655:role/testrole1"), StringVal("arn:aws:iam::218925562655:role/testrole2")))
# if s.check() == sat:
#     print(s.model())
# else:
#     print('unsat 2')


s = Solver()
s.add(NonEmptyRegexIntersect(iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole2/testrolesession"), 
                                iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole1/*")))
                            
print(iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole2/testrolesession"))
print(iam_pattern_to_regex("arn:aws:sts::218925562655:assumed-role/testrole1/*"))

if s.check() == sat:
    print(s.model())
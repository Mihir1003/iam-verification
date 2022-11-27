from z3 import BoolSort, StringSort, Strings, InRe, And, BoolVal, \
     StringVal, Or, TransitiveClosure, RecAddDefinition, RecFunction, String,\
     SetAdd, EmptySet, IsMember, Array, Store, Select, simplify, Contains, Solver, sat,\
     Intersect, FreshConst, ReSort, Re, Distinct, If, Empty, Not

from id_match import iam_pattern_to_regex

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
                    InRe(a, iam_pattern_to_regex("s3:*")),
                    InRe(r, iam_pattern_to_regex("*")))
    )

Access = RecFunction('Access', StringSort(), StringSort(), BoolSort())
u1, u2 = Strings('u1 u2')
RecAddDefinition(Access, [u1, u2], 
    Or(u1 == u2, 
                 Policy(BoolVal(True), u1, StringVal("sts:AssumeRole"), u2))
)
TC_Access = TransitiveClosure(Access)

def Allow(u, a, r):
    q = FreshConst(StringSort())
    return And(TC_Access(u, q), 
        Policy(BoolVal(True), q, a, r))



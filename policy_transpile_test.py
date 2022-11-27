import unittest
from z3 import Solver, sat, unsat, StringVal, BoolVal, prove, InRe, And, Or, FreshConst, BoolSort, StringSort,\
 ForAll
from id_match import iam_pattern_to_regex
from policy import createPolicyFunction, usePolicyConstraints, generatePolicyConstraints, flat_map, extract,\
    createPolicyFunction, transpileAll

def Policy(e, u, a, r):
        return Or(
            And(
            e == BoolVal(True),
            u == StringVal("arn:aws:iam::218925562655:user/test1"), 
            InRe(a, iam_pattern_to_regex("sts:*")),
            InRe(r, iam_pattern_to_regex("arn:aws:iam::218925562655:role/testrole*"))),
                    

            And(e == BoolVal(True),
                u == StringVal("arn:aws:iam::218925562655:role/testrole2"),
                    InRe(a, iam_pattern_to_regex("s3:*")),
                    InRe(r, iam_pattern_to_regex("*"))))

policies = {
        "arn:aws:iam::218925562655:user/test1": {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "VisualEditor1",
                            "Effect": "Allow",
                            "Action": "sts:*",
                            "Resource": "arn:aws:iam::218925562655:role/testrole*"
                        }
                    ]
                },
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "CreateDate": "2022-11-21T06:45:18+00:00"
            }
        },
        "arn:aws:iam::218925562655:role/testrole2": {
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
                "IsDefaultVersion": False,
                "CreateDate": "2015-02-06T18:40:58+00:00"
            }
        }
    }

class PolicyTranspileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        env = transpileAll()
        cls.Policy, cls.Access, cls.TC_Access, cls.Allow = env['Policy'], env['Access'], env['TC_Access'], env['Allow']

    def assertSat(self, constraint):
        s = Solver()
        s.add(constraint)
        self.assertEqual(s.check(), sat)
        print(s.model())
    
    def assertUnsat(self, constraint):
        s = Solver()
        s.add(constraint)
        self.assertEqual(s.check(), unsat)

    def test_policy_transpile(self):
        #self.assertTrue(False)
        #print("here")
        compiled_policy_fn = createPolicyFunction(zip(policies.keys(), flat_map(extract, policies.values())))

        e, u, a, r = (FreshConst(BoolSort()), FreshConst(StringSort()),
                        FreshConst(StringSort()), FreshConst(StringSort()))

        self.assertSat(ForAll([e, u, a, r], compiled_policy_fn(e, u, a, r) == Policy(e, u, a, r)))
    
    def test_access_reflexive(self):
        self.assertSat(self.Access(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("arn:aws:iam::218925562655:user/test1")))
    
    def test_access_user_role(self):
        self.assertSat(self.Access(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("arn:aws:iam::218925562655:role/testrole1")))
    
    def test_access_role_role(self):
         self.assertSat(self.Access(StringVal("arn:aws:iam::218925562655:role/testrole1"), StringVal("arn:aws:iam::218925562655:role/testrole2")))
    
    def test_access_transitive(self):
        self.assertSat(self.TC_Access(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("arn:aws:iam::218925562655:role/testrole2")))
    
    def test_allow_transitive(self):
        self.assertSat(self.__class__.Allow(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("s3:GetObject"), StringVal("TestObject")))
    
    def test_not_allow_transitive(self):
        self.assertUnsat(self.__class__.Allow(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("dynamodb:BatchGetItem"), StringVal("TestObject")))

if __name__ == "__main__":
    unittest.main()
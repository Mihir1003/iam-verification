import unittest
from example_model import Access, Allow, Policy, TC_Access
from z3 import Solver, BoolVal, StringVal, sat, unsat

class ExampleModelTest(unittest.TestCase):
    def assertSat(self, prop):
        s = Solver()
        s.add(prop)
        self.assertEqual(s.check(), sat)
    
    def assertUnsat(self, prop):
        s = Solver()
        s.add(prop)
        self.assertEqual(s.check(), unsat)

    def test_policy_1(self):
        self.assertSat(Policy(BoolVal(True), StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("sts:Assume"),
                                StringVal("arn:aws:iam::218925562655:role/testrole1")))
    
    def test_access_reflexive(self):
        self.assertSat(Access(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("arn:aws:iam::218925562655:user/test1")))
    
    def test_access_user_role(self):
        self.assertSat(Access(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("arn:aws:iam::218925562655:role/testrole1")))
    
    def test_access_role_role(self):
        self.assertSat(Access(StringVal("arn:aws:iam::218925562655:role/testrole1"), StringVal("arn:aws:iam::218925562655:role/testrole2")))
    
    def test_access_transitive(self):
        self.assertSat(TC_Access(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("arn:aws:iam::218925562655:role/testrole2")))
    
    def test_allow_transitive(self):
        self.assertSat(Allow(StringVal("arn:aws:iam::218925562655:user/test1"), StringVal("s3:GetObject"), StringVal("TestObject")))
        
if __name__ == "__main__":
    unittest.main()
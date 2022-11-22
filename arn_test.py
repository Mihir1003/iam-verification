import unittest
from arn import ARN

class ArnTest(unittest.TestCase):
    def test_arn_iam_role(self):
        test_arn = "arn:aws:iam::218925562655:role/testrole1"
        self.assertEqual(ARN.parse(test_arn),
                         ARN(partition='aws',
                                service='iam',
                                region='',
                                account_id='218925562655',
                                resource_type='role',
                                resource_id='testrole1'))
    
    def test_arn_sts_role_session(self):
        test_arn = "arn:aws:sts::218925562655:assumed-role/testrole1/testrolesession"
        self.assertEqual(ARN.parse(test_arn), 
                            ARN(partition='aws',
                                service='sts',
                                region='',
                                account_id='218925562655',
                                resource_type='assumed-role',
                                resource_id='testrole1/testrolesession'))
    
    def test_arn_iam_user(self):
        test_arn = "arn:aws:iam::218925562655:user/test3"
        self.assertEqual(ARN.parse(test_arn), ARN(partition='aws', 
                                    service='iam',
                                    region='',
                                    account_id='218925562655',
                                    resource_type='user',
                                    resource_id='test3'))

if __name__ == "__main__":
    unittest.main()
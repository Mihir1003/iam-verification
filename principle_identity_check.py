import re
from z3 import *

"""
identity is an arn
principal is a pattern which specifies a principal
"""
def is_part_of_principle(identity,principle):
    """
    [fdni]*
    iam , user, *
    iam:user:hello
    """
    return 
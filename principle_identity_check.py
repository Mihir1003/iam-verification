import re
from z3 import *



def is_part_of_principle(identity,principle):
    """
    [fdni]*
    iam , user, *
    iam:user:hello
    """
    return 
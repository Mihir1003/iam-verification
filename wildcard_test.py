import resource
import unittest
from id_match import WILDCARD_QUESTION_REGEX, iam_pattern_to_regex, WILDCARD_STAR_REGEX
from functools import reduce
import z3

def concat(*res):
    return reduce(z3.Concat, res)

class WildcardTest(unittest.TestCase):
    def assertMatches(self, test_str, reg):
        s = z3.Solver()
        s.add(z3.InRe(z3.StringVal(test_str), reg))
        self.assertTrue(s.check() == z3.sat)

    def assertNotMatches(self, test_str, reg):
        s = z3.Solver()
        s.add(z3.InRe(z3.StringVal(test_str), reg))
        self.assertTrue(s.check() == z3.unsat)
        
    def test_id_no_wildcards(self):
        id = "arn:aws:iam::account-ID-without-hyphens:user/Bob"
        self.assertEqual(iam_pattern_to_regex(id), z3.Re("arn:aws:iam::account-ID-without-hyphens:user/Bob"))

        self.assertMatches(id, iam_pattern_to_regex(id))

    def test_id_single_wildcard_end(self):
        id = "arn:aws:iam::account-ID-without-hyphens:user/Bob/*"
        self.assertEqual(iam_pattern_to_regex(id), z3.Concat(z3.Re("arn:aws:iam::account-ID-without-hyphens:user/Bob/"),
                                                                WILDCARD_STAR_REGEX))
         
        self.assertMatches("arn:aws:iam::account-ID-without-hyphens:user/Bob/1abc243d75", iam_pattern_to_regex(id))

    def test_id_single_wildcard_beginning(self):
        self.assertEqual(iam_pattern_to_regex("*arn:aws:iam::account-ID-without-hyphens:user/Bob/"), 
                                    concat(WILDCARD_STAR_REGEX, z3.Re("arn:aws:iam::account-ID-without-hyphens:user/Bob/")))

    def test_id_wildcard_middle(self):
        id = "arn:aws:iam::account-ID-without-hyphens*:user/Bob/"
        self.assertEqual(
            iam_pattern_to_regex("arn:aws:iam::account-ID-without-hyphens*:user/Bob/"),
            z3.Concat(z3.Concat(z3.Re("arn:aws:iam::account-ID-without-hyphens"), WILDCARD_STAR_REGEX), z3.Re(":user/Bob/")))
        
        self.assertMatches("arn:aws:iam::account-ID-without-hyphens_fpc3-=@5:user/Bob/", iam_pattern_to_regex("arn:aws:iam::account-ID-without-hyphens*:user/Bob/"))
    
    def test_id_multiple_wildcard_middle(self):
        pat = "arn:aws:ia?::account-ID-without-hyphens:user*/Bob/"
        self.assertEqual(iam_pattern_to_regex(pat),
            z3.Concat(z3.Concat(z3.Concat(z3.Concat(z3.Re("arn:aws:ia"), WILDCARD_QUESTION_REGEX), z3.Re("::account-ID-without-hyphens:user")), WILDCARD_STAR_REGEX),
                    z3.Re("/Bob/")))
        
        self.assertMatches("arn:aws:iam::account-ID-without-hyphens:userabcdef32c/Bob/", iam_pattern_to_regex(pat))
    
    def test_star_question_together(self):
        self.assertEqual(iam_pattern_to_regex("arn:aws:ia::account-ID-without-hyphens:user*?/Bob/"), 
            z3.Concat(z3.Concat(z3.Concat(z3.Re("arn:aws:ia::account-ID-without-hyphens:user"), WILDCARD_STAR_REGEX), WILDCARD_QUESTION_REGEX),
                        z3.Re("/Bob/")))

    def test_star_question_together_end_of_string(self):
        self.assertEqual(iam_pattern_to_regex("arn:aws:ia::account-ID-without-hyphens:user/Bob/*?"),
                            concat(z3.Re("arn:aws:ia::account-ID-without-hyphens:user/Bob/"),
                                    WILDCARD_STAR_REGEX, WILDCARD_QUESTION_REGEX))
    
    def test_star_question_together_beg_of_string(self):
        self.assertEqual(iam_pattern_to_regex("*?arn:aws:ia::account-ID-without-hyphens:user/Bob/"),
                            concat(WILDCARD_STAR_REGEX, WILDCARD_QUESTION_REGEX, z3.Re("arn:aws:ia::account-ID-without-hyphens:user/Bob/")))
    
    def test_only_wildcards(self):
        self.assertEqual(iam_pattern_to_regex("*"), WILDCARD_STAR_REGEX)
        self.assertMatches("f792e4@", iam_pattern_to_regex("*"))
        self.assertNotMatches("^f792e4@$", iam_pattern_to_regex("*"))
        self.assertMatches("", iam_pattern_to_regex("*"))

        self.assertEqual(iam_pattern_to_regex("?"), WILDCARD_QUESTION_REGEX)
        self.assertMatches("_", iam_pattern_to_regex("?"))
        self.assertNotMatches("ab", iam_pattern_to_regex("?"))
        self.assertNotMatches("^", iam_pattern_to_regex("?"))
        self.assertNotMatches("", iam_pattern_to_regex("?"))

if __name__ == "__main__":
    unittest.main()
import resource
import unittest
from id_match import WILDCARD_QUESTION_REGEX, resource_id_to_regex, WILDCARD_STAR_REGEX
from functools import reduce
import z3

def concat(*res):
	return reduce(z3.Concat, res)

class WildcardTest(unittest.TestCase):
	def test_id_no_wildcards(self):
		id = "arn:aws:iam::account-ID-without-hyphens:user/Bob"
		self.assertEqual(resource_id_to_regex(id), z3.Re("arn:aws:iam::account-ID-without-hyphens:user/Bob"))

	def test_id_single_wildcard_end(self):
		id = "arn:aws:iam::account-ID-without-hyphens:user/Bob/*"
		self.assertEqual(resource_id_to_regex(id), z3.Concat(z3.Re("arn:aws:iam::account-ID-without-hyphens:user/Bob/"),
																WILDCARD_STAR_REGEX))

	def test_id_single_wildcard_beginning(self):
		self.assertEqual(resource_id_to_regex("*arn:aws:iam::account-ID-without-hyphens:user/Bob/"), 
									concat(WILDCARD_STAR_REGEX, z3.Re("arn:aws:iam::account-ID-without-hyphens:user/Bob/")))

	def test_id_wildcard_middle(self):
		self.assertEqual(
			resource_id_to_regex("arn:aws:iam::account-ID-without-hyphens*:user/Bob/"),
			z3.Concat(z3.Concat(z3.Re("arn:aws:iam::account-ID-without-hyphens"), WILDCARD_STAR_REGEX), z3.Re(":user/Bob/")))
	
	def test_id_multiple_wildcard_middle(self):
		self.assertEqual(resource_id_to_regex("arn:aws:ia?::account-ID-without-hyphens:user*/Bob/"),
			z3.Concat(z3.Concat(z3.Concat(z3.Concat(z3.Re("arn:aws:ia"), WILDCARD_QUESTION_REGEX), z3.Re("::account-ID-without-hyphens:user")), WILDCARD_STAR_REGEX),
					z3.Re("/Bob/")))
	
	def test_star_question_together(self):
		self.assertEqual(resource_id_to_regex("arn:aws:ia::account-ID-without-hyphens:user*?/Bob/"), 
			z3.Concat(z3.Concat(z3.Concat(z3.Re("arn:aws:ia::account-ID-without-hyphens:user"), WILDCARD_STAR_REGEX), WILDCARD_QUESTION_REGEX),
						z3.Re("/Bob/")))


	def test_star_question_together_end_of_string(self):
		self.assertEqual(resource_id_to_regex("arn:aws:ia::account-ID-without-hyphens:user/Bob/*?"),
							concat(z3.Re("arn:aws:ia::account-ID-without-hyphens:user/Bob/"),
									WILDCARD_STAR_REGEX, WILDCARD_QUESTION_REGEX))
	
	def test_star_question_together_beg_of_string(self):
		self.assertEqual(resource_id_to_regex("*?arn:aws:ia::account-ID-without-hyphens:user/Bob/"),
							concat(WILDCARD_STAR_REGEX, WILDCARD_QUESTION_REGEX, z3.Re("arn:aws:ia::account-ID-without-hyphens:user/Bob/")))
	
	def test_only_wildcards(self):
		self.assertEqual(resource_id_to_regex("*"), WILDCARD_STAR_REGEX)

if __name__ == "__main__":
	unittest.main()
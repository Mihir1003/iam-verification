import z3
import string
import re
from functools import reduce
import itertools

SPECIAL_CHARS = reduce(z3.Union, map(z3.Re, "+=,.@_-"))
ASCII_UPPERCASE = z3.Range(string.ascii_uppercase[0], string.ascii_uppercase[-1])
ASCII_LOWERCASE = z3.Range(string.ascii_lowercase[0], string.ascii_lowercase[-1])
ASCII_DIGITS = z3.Range(string.digits[0], string.digits[-1])
ALPHANUMERIC = z3.Union(ASCII_UPPERCASE,
                        ASCII_LOWERCASE,
                        ASCII_DIGITS)

# a wildcard '*' matches 0 or more valid id characters
WILDCARD_STAR_REGEX = z3.Star(z3.Union(ALPHANUMERIC, SPECIAL_CHARS))

# the wildcard '?' matches a single valid id character
WILDCARD_QUESTION_REGEX = z3.Union(ALPHANUMERIC, SPECIAL_CHARS)

"""
we assume a pattern looks like the following:

wild_card = '*' | '?'
special_char ::= + | = | , | . | @ | _ | - 
id_char ::= [aA-zZ0-9] | special_char | wild_card 
arn_component ::= id_char* | arn_component ':' arn_component
"""

def to_wildcard(wildcard_char: str):
	if wildcard_char == '*':
		return WILDCARD_STAR_REGEX
	elif wildcard_char == '?':
		return WILDCARD_QUESTION_REGEX
	else:
		raise ValueError(f'unknown wildcard {wildcard_char}')

# converts an AWS wildcard pattern to a z3 regex which matches that string
def iam_pattern_to_regex(pattern: str):
	wildcards = re.findall(r"\*|\?", pattern)
	parts = re.split(r"\*|\?", pattern)

	# a list of z3 regexes for the wildcard components
	wildcard_regexes = list(map(to_wildcard, wildcards))

	# a list of z3 regexes for the non-wildcard components
	const_regexes = list(map(z3.Re, parts))

	# we split the list into [non-wildcard, wildcard] chunks, and add them all together, padding with the empty regex.
	# even if a wildcard occurs at the beginning or end a string, i.e. "*abcd", re.split will add an extra ''
	# so we will always have a (maybe empty) non-wildcard string before the wildcard
	regex_components = itertools.chain(*([part, wildcard] for (part, wildcard) in itertools.zip_longest(const_regexes, wildcard_regexes, fillvalue=z3.Re(''))))

	# filter out trivial regex
	no_trivial = filter(lambda r: not z3.Re('').eq(r), regex_components)
	
	return reduce(z3.Concat, no_trivial)
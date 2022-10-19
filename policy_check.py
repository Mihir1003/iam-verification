from typing import Any, Dict, List, Union
import z3

def compile_principal_constraints(principal: str):
	return # constraint expression

def compile_action_constraints(action: str):
	pass

def compile_resource_constraints(resources: Union[str, List[str]]):
	pass

def compile_policy(policy: Dict[str, Any]):
	solver = z3.Solver()
	# Add Constraints:
		# Effect
		# Principal
		# Action (possibly multiple/unlimited)
		# Resource(s):
	
	return solver
	
def policy_check(policy: Dict[str, Any], principal: str, action: str):
	pass
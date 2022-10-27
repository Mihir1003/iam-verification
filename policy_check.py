from typing import Any, Dict, List, Tuple, Union
import z3

def compile_principal_constraints(principal: str):
	return 	z3.SetAdd(z3.EmptySet(z3.StringSort()),z3.StringVal(principal))

def compile_action_constraints(action: str):
	return  z3.SetAdd(z3.EmptySet(z3.StringSort()),z3.StringVal(action))

def compile_resource_constraints(resources: Union[str, List[str]]):
	resources_set = z3.SetAdd(z3.EmptySet(z3.StringSort())))
	for resource in resources:
		resources_set = z3.SetAdd(resources_set,z3.StringVal(resource))
	return resources_set

def compile_statement(statement : Tuple(str, Any)):
	match statement[0] :
		case "Principle":
			return (z3.String(statement[0]),compile_principal_constraints(statement[1]))
		case "Action":
			return (z3.String(statement[0]),compile_action_constraints(statement[1]))
		case "Resource": 
			return (z3.String(statement[0]),compile_resource_constraints(statement[1]))
		case default:
			raise 



def compile_policy(policy: Dict[str, Any]):
	constraints = []
	for statement in policy.items() :
		c,state = (compile_statement(statement))
		constraints.append(z3.isMember(z3.String(c),state))
	return z3.And(*constraints)

def verify_statement(constraint, query):
	return z3.String(constraint) == z3.StringVal(query)

def verify_statements(verfiy_policy: Dict[str, Any]):
	constraints = []
	for statement in verfiy_policy.items() :
		state = (verify_statement(statement))
		constraints.append(state)
	return z3.And(*constraints)

def policy_check(policy: Dict[str, Any], principal: str, action: str):
	s = z3.Solver()
	s.add(compile_policy, policy)
	s.add(verify_statements(dict([("Principal",principal),("Action",action)])))
	assert s.check() == z3.sat
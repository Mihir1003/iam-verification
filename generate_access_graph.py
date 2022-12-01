from collections import defaultdict
from dataclasses import dataclass
import time
from typing import Any, List
import random
import os
import enum
import networkx as nx
import itertools
from iam import extract
from z3 import Solver, String, Bool, StringVal, sat

from policy import transpile

random.seed(1234)

ACCOUNT_ID = int.from_bytes(random.randbytes(8), "little")

S3_BUCKET_ACTIONS = [
    "s3:GetObject",
    "s3:GetObjectAcl",
    "s3:GetObjectRetention",
    "s3:InitiateReplication",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:PutObject"
]

STS_ACTIONS: list[str] = [
    "sts:AssumeRole",
    "sts:*"
]

@dataclass
class Statement:
    effect: bool # True for allow, False for deny
    actions: list[str] # pattern representing resource
    resources: list[str] # pattern representing resource this policy applies to

@dataclass
class Policy:
    statements: list[Statement]

def policy_to_dict(p: Policy) -> dict[str, Any]:
    return {
         'PolicyVersion': {
            'Document': {
                'Statement': list(map(statement_to_dict, p.statements))
            }
        }
    }
    
def statement_to_dict(s: Statement):
    return {
            'Effect': 'Allow' if s.effect else 'Deny',
            'Action': s.actions,
            'Resource': s.resources
    }

class IDKind(enum.Enum):
    USER = 0
    ROLE = 1
    def __str__(self):
        match self.value:
            case 0: return "user"
            case 1: return "role"
            case _: raise ValueError("unknown id kind")

def format_arn(account_id, user_name, id_kind = IDKind.USER):
    return f"arn:aws:iam::{account_id}:{id_kind}/{user_name}"

def format_user_id(n):
    return f"user_{n}"

def generate_user_policies(role_groups, n=10):
    user_policies = []
    role_to_user = defaultdict(list)
    for i in range(1, n+1):
        role_group_id = random.choice(range(len(role_groups)))
        user_arn = format_arn(ACCOUNT_ID, format_user_id(i), IDKind.USER)
        role_arn = format_arn(ACCOUNT_ID, format_role_group(role_group_id), IDKind.ROLE)
        policy = generate_user_policy(role_arn)
        for role in role_groups[role_group_id]:
            role_to_user[role].append(user_arn)
        user_policies.append((user_arn, policy))
    return (user_policies, role_to_user)

def format_test_object(id):
    return f"test_object_{id}"

def next_test_object_id():
    c = 1
    while 1:
        yield format_test_object(c)
        c += 1
next_test_object = next_test_object_id()

def generate_test_object():
    return next(next_test_object)

def generate_test_objects_for_policy(num_objects):
    return [generate_test_object() for _ in range(num_objects)]

def generate_role_policy(n_objects, n_actions, connected):
    resources = generate_test_objects_for_policy(n_objects)
    actions = random.sample(S3_BUCKET_ACTIONS, k=n_actions) 
    resource_stmt = Statement(True, actions, resources) 
    assume_stmt = Statement(True, [random.choice(STS_ACTIONS)], connected)
    return Policy([resource_stmt, assume_stmt])

def collapse_to_action_resource_pairs(policy):
    pairs = []
    for stmt in policy.statements:
        for act in stmt.actions:
            for res in stmt.resources:
                pairs.append((act, res))
    
    return pairs

def generate_role_policies(role_graph, max_n_objects, max_n_actions):
    role_policies = []
    role_action_resource_pairs = {}
    for role in role_graph:
        rp = generate_role_policy(random.randint(1, max_n_objects), 
                                random.randint(1,  max_n_actions),
                                role_graph[role])
        role_action_resource_pairs[role] = collapse_to_action_resource_pairs(rp)

        role_policies.append((role, rp))
    
    return (role_policies, role_action_resource_pairs)

def format_role(group_i, role_i):   
    return f"role_r{group_i}_{role_i}"

def format_role_group(group_i):   
    return f"role_r{group_i}"

def generate_roles(num_role_groups=5, max_role_group_size=4):
    return [[format_arn(ACCOUNT_ID, format_role(i, j), IDKind.ROLE) for j in range(1, random.randint(1, max_role_group_size)+1)]
             for i in range(num_role_groups)]
    
def generate_role_assumption_graph(roles: list[str], branching_factor=2):
    adj = defaultdict(list)
    seen = set()
    for role in roles:
        seen.add(role)
        connected_roles = list(filter(lambda r: r not in seen, random.sample(roles, min(len(roles), branching_factor))))
        adj[role] = connected_roles
    return adj

def flatten(roles):
    return [r for group in roles for r in group]

def to_digraph(adj):
    flattened = [(r1, r2) for r1 in adj for r2 in adj[r1]]
    return nx.DiGraph(flattened)

def generate_user_policy(role_arn):
    return Policy([Statement(True, [random.choice(STS_ACTIONS)], [f"{role_arn}*"])])

@dataclass
class IAMTestConfiguration:
    # the params used for generating this test
    params: dict[str, int]
    # the compiled test environment
    env: dict[str, Any]
    # mapping from role to list of users that can assume said role
    role_to_user: dict[str, list[str]]
    # mapping from role to (action, resource) pairs
    role_to_action_resource_pairs: dict[str, list[tuple[str, str]]]

    role_graph: nx.DiGraph

    def generate_allow_test(self):
        lp = nx.dag_longest_path(self.role_graph)
        user = random.choice(self.role_to_user[lp[0]])
        action, resource = random.choice(self.role_to_action_resource_pairs[lp[-1]])

        return (user, action, resource, len(lp))

def generate_iam_test(params):
    roles = generate_roles(num_role_groups=params['num_role_groups'])
    adj = generate_role_assumption_graph(flatten(roles), branching_factor=params['role_branching_factor'])

    user_policies, role_to_user  = generate_user_policies(roles, n=params['num_users'])
    role_policies, role_to_pairs = generate_role_policies(adj, max_n_objects=params['max_n_objects'], max_n_actions=params['max_n_actions'])

    policy_dicts = flat_map(extract, map(lambda user_policy: policy_to_dict(user_policy[1]), user_policies))
    policy_arns =  flat_map(lambda user_policy: [user_policy[0]]*len(user_policy[1].statements), user_policies)

    role_dicts = flat_map(extract, map(lambda role_policy: policy_to_dict(role_policy[1]), role_policies))
    role_arns =  flat_map(lambda role_policy: [role_policy[0]]*len(role_policy[1].statements), role_policies)
    all_policies = list(zip(policy_arns, policy_dicts)) + list(zip(role_arns, role_dicts))
    env = transpile(all_policies)

    return IAMTestConfiguration(params, env, role_to_user, role_to_pairs, nx.DiGraph(adj))

#:print(users)

# dg = to_digraph(adj)
# print(nx.dag_longest_path(dg))



def flat_map(f, xs):
     return (y for ys in xs for y in f(ys))

# dg = to_digraph(adj)
# lp = nx.dag_longest_path(dg)
# print(lp)

# #transpile(user_policies)
# env = transpile(all_policies)
# s = Solver()
# e = Bool('e')
# u = String('u')
# a = String('a')
# r = String('r')
# user = random.choice(role_to_user[lp[0]])
# act, res = random.choice(role_to_pairs[lp[-1]])
# #print(role_to_pairs)
# print(f"{act}, {res}")

# s.add(env['Allow'](StringVal(user), StringVal(act), StringVal(res)))

# res, elapsed = time_function(lambda: s.check())
# if res == sat: 
#     print('sat')
#     #print(s.model())
# else:
#     print('unsat')
# print(f"elapsed: {elapsed}")

# # print(role_to_user)
# # print(role_to_pairs)
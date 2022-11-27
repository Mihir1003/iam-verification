import boto3
import json
from functools import cache

''' 

output needed

get all users
   - get all policies
   - get all groups
        - get all polcies

get all roles
   - get all policies
list of [policy, identity arn]



'''

iam = boto3.client("iam")


flat_map = lambda f, xs: (y for ys in xs for y in f(ys))


def get(key):
    return lambda x : x[key]

def extract(policy):
    return policy["PolicyVersion"]["Document"]["Statement"]

@cache
def fetch_policy(arn):
    policy_metadata = iam.get_policy(PolicyArn=arn)
    return iam.get_policy_version(PolicyArn=arn,VersionId=policy_metadata["Policy"]["DefaultVersionId"])
     

def fetch_users():
    return iam.list_users()["Users"]

def fetch_user_attached_polcies(user):
    return iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]

def fetch_user_inline_polcies(user):
    policy_names =  iam.list_user_policies(UserName=user)["PolicyNames"]
    policies= map(lambda x : iam.get_user_policy(UserName=user,PolicyName=x),policy_names)
    return list(flat_map(get("Statement"),map(get("PolicyDocument"),policies)))
    
@cache
def fetch_group_inline_polcies(group):
    policy_names =  iam.list_group_policies(GroupName=group)["PolicyNames"]
    policies = map(lambda x : iam.get_group_policy(GroupName=group,PolicyName=x),policy_names)
    return list(flat_map(get("Statement"),map(get("PolicyDocument"),policies)))


def fetch_groups_for_user(user):
    return iam.list_groups_for_user(UserName=user)["Groups"]

@cache
def fetch_group_attached_polcies(group):
    return iam.list_attached_group_policies(GroupName=group)["AttachedPolicies"]

def fetch_all_polcies_for_user(user):
    groups = fetch_groups_for_user(user)
    policies = list(flat_map(fetch_group_attached_polcies,map(get("GroupName"),groups)))
    policies+=fetch_user_attached_polcies(user)
    managed_polcies =  list(flat_map(extract,map(fetch_policy,map(get("PolicyArn"),policies))))
    inline_policies =  list(flat_map(fetch_group_inline_polcies,map(get("GroupName"),groups))) + list(fetch_user_inline_polcies(user))
    return managed_polcies + inline_policies
    
def fetch_roles():
    return iam.list_roles()["Roles"]

def fetch_role_attached_polcies(role):
    return iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]

def fetch_role_inline_polcies(role):
    policy_names =  iam.list_role_policies(RoleName=role)["PolicyNames"]
    policies= map(lambda x : iam.get_role_policy(RoleName=role,PolicyName=x),policy_names)
    return flat_map(get("Statement"),map(get("PolicyDocument"),policies))

def fetch_all_polcies_for_role(role):
    policies=fetch_role_attached_polcies(role)
    managed_polcies =  list(flat_map(extract,map(fetch_policy,map(get("PolicyArn"),policies))))
    # print(managed_polcies)
    inline_policies = list(fetch_role_inline_polcies(role))
    # print(inline_policies)
    return managed_polcies + inline_policies

def mapIdentityToPolicies(identity,policies):
    for p in policies:
        yield (identity,p)

def transformPolicyArray(ips):
    ip=[]
    for i,p in ips:
        ip+=list(mapIdentityToPolicies(i,p))
    return ip
    #  return list(zip([identity]*len(policies),policies))

def get_all_identities_with_policies():
    users = fetch_users()
    users_polcies = list(zip(map(get("Arn"),users),map(fetch_all_polcies_for_user,map(get("UserName"),users))))
    # print(users_polcies)
    print("Fetched User Polcies")
    roles = fetch_roles()
    roles_polcies = list(zip(map(get("Arn"),roles),map(fetch_all_polcies_for_role,map(get("RoleName"),roles))))
    # print(roles_polcies)
    print("Fetch Role Polcies")
    return users_polcies + roles_polcies
#transformPolicyArray(get_all_identities_with_policies())
# print(get_all_identities_with_policies())
# print(list(flat_map(lambda x: mapIdentityToPolicies(*x),get_all_identities_with_policies())))
# groups = []
# paginator = iam.get_paginator('list_groups')
# for response in paginator.paginate():
#     for group in response["Groups"]:
#         groupName = group["GroupName"]
#         arn = group["Arn"]
#         print(group)
#         response = iam.list_attached_group_policies(
#             GroupName=groupName
#         )
#         print(groupName)
#         print(response["AttachedPolicies"])
#         groups.append({"name":groupName,"GroupArn":arn,"policies":response["AttachedPolicies"]})
# print(groups)
# print('''


# ''')
# paginator = iam.get_paginator('list_roles')
# for response in paginator.paginate():
#     for role in response["Roles"]:
#         roleName = role["RoleName"]
#         arn = role["Arn"]
#         print(role)
#         response = iam.list_attached_role_policies(
#             RoleName=roleName
#         )
#         print(roleName)
#         print(response["AttachedPolicies"])
#         #groups.append({"name":groupName,"GroupArn":arn,"policies":response["AttachedPolicies"]})
# #print(groups)
# print('''


# ''')
# paginator = iam.get_paginator('list_users')
# for response in paginator.paginate():
#     for user in response["Users"]:
#         userName = user["UserName"]
#         arn = user["Arn"]
#         response = iam.list_attached_user_policies(
#             UserName=userName
#         )
#         print(userName)
#         print(response["AttachedPolicies"])
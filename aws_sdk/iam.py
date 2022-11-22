import boto3
import json

iam = boto3.client("iam")

groups = []
paginator = iam.get_paginator('list_groups')
for response in paginator.paginate():
    for group in response["Groups"]:
        groupName = group["GroupName"]
        arn = group["Arn"]
        print(group)
        response = iam.list_attached_group_policies(
            GroupName=groupName
        )
        print(groupName)
        print(response["AttachedPolicies"])
        groups.append({"name":groupName,"GroupArn":arn,"policies":response["AttachedPolicies"]})
print(groups)
print('''


''')
paginator = iam.get_paginator('list_roles')
for response in paginator.paginate():
    for role in response["Roles"]:
        roleName = role["RoleName"]
        arn = role["Arn"]
        print(role)
        response = iam.list_attached_role_policies(
            RoleName=roleName
        )
        print(roleName)
        print(response["AttachedPolicies"])
        #groups.append({"name":groupName,"GroupArn":arn,"policies":response["AttachedPolicies"]})
#print(groups)
print('''


''')
paginator = iam.get_paginator('list_users')
for response in paginator.paginate():
    for user in response["Users"]:
        userName = user["UserName"]
        arn = user["Arn"]
        response = iam.list_attached_user_policies(
            UserName=userName
        )
        print(userName)
        print(response["AttachedPolicies"])
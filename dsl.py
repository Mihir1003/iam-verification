from z3 import *

'''
Can(
	Identity("User")
	Perform("Read"),
	On("SomeResource")
)

assert	Identity("User").can.Perform("Read").On("SomeResource")

=> 


class Identity(arn)
     can() -> Can

class Can 
    perform() -> Perform()

class Perform(action)
    on() -> On()

class On(arn) -> bool

'''

class Resource():
    def __init__(self,iam,effect,action,resource):
        self.identity = iam
        self.effect = effect
        self.action = action
        self.resource = resource

    def check(self):
        createPolcyFunction(StringVal(self.identity), StringVal("s3:GetObject"), StringVal("TestObject")))
        contraint = (Access(StringVal(self.identity), StringVal("s3:GetObject"), StringVal("TestObject")))
        s = solver()
        s.add(contraint)
        want = s.check()
        return want == sat if self.effect else want == unsat



class Perform():
    def __init__(self,iam,effect,action):
        self.identity = iam
        self.effect = effect
        self.action = action

    def on(arn):
        return Resource(self.identity,self.effect,self.action,arn)

class Can:
    def __init__(self,iam):
        self.identity = iam
        self.effect = True
    
    def perform(action):
        return Perform(self.identity,effect,action)

class Cannot:
    def __init__(self,iam):
        self.effect = False
    
    def perform(action):
        return Perform(self.identity,effect,action)


class Identity:

    def __init__(self,arn):
        self.identity = arn

    def can():
        return Can(self.identity)
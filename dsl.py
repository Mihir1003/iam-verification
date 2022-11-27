from z3 import Solver, sat, unsat, StringVal
from policy import createPolicyFunction, transpileAll

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
ENV = None
DEBUG = True

class Resource():
    def __init__(self,iam,effect,action,resource):
        self.identity = iam
        self.effect = effect
        self.action = action
        self.resource = resource

    def check(self):
       # createPolcyFunction(StringVal(self.identity), StringVal("s3:GetObject"), StringVal("TestObject")))
        #contraint = (Access(StringVal(self.identity), StringVal("s3:GetObject"), StringVal("TestObject")))

        constraint = ENV['Allow'](StringVal(self.identity), StringVal(self.action), StringVal(self.resource))
        if DEBUG:
            print(f"Checking constraint: {constraint}")
        s = Solver()
        s.add(constraint)
        result = s.check()
        return result == sat if self.effect else result == unsat

class Perform():
    def __init__(self,iam,effect,action):
        self.identity = iam
        self.effect = effect
        self.action = action

    def on(self, arn):
        return Resource(self.identity,self.effect,self.action,arn)

class Can:
    def __init__(self, iam):
        self.identity = iam
        self.effect = True
    
    def perform(self, action):
        return Perform(self.identity, self.effect, action)

class Cannot:
    def __init__(self,iam):
        self.identity = iam
        self.effect = False
    
    def perform(self, action):
        return Perform(self.identity, self.effect, action)


class Identity:
    def __init__(self,arn):
        self.identity = arn

    def can(self):
        return Can(self.identity)

    def cannot(self):
        return Cannot(self.identity)

if __name__ == "__main__":
    ENV = transpileAll()

    r1 = Identity("arn:aws:iam::218925562655:user/test1")\
        .can()\
        .perform("s3:getObject")\
        .on("TestObject")\
        .check()
    
    print(f"result1={r1}")
    
    r2 = Identity("arn:aws:iam::218925562655:user/test2")\
        .can()\
        .perform("s3:getObject")\
        .on("TestObject")\
        .check()

    print(f"result2={r2}")

    r3 = Identity("arn:aws:iam::218925562655:user/test1")\
        .cannot()\
        .perform("s3:getObject")\
        .on("TestObject")\
        .check()
    
    print(f"result3={r3}")

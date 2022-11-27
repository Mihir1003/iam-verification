### compile policies to z3 constraints

from typing import Dict, Any, Iterator
from enum import Enum
import json

class EntityType(Enum):
    IAM_ROLE = 0
    UNKNOWN = 1

class PolicyCompiler:
    def infer_entity_type(self, policy: Dict[str, Any]) -> EntityType:
        if 'Role' in policy:
            return EntityType.IAM_ROLE
        return EntityType.UNKNOWN

    def compile_entity(self, entity: Dict[str, Any]):
        # dispatch based on type of policy:
        match self.infer_entity_type(entity):
            case EntityType.IAM_ROLE:
                self.compile_iam_role(entity)
            case _:
                raise ValueError('Unknown entity type')
    
    def compile_iam_role(self, role_json: Dict[str, Any]):
        pass

    def read_entities(self, *files: str) -> Iterator[Any]:
        for file_name in files:
            try: 
                f = open(file_name, 'r')
            except IOError as e:
                raise e
            yield json.load(f)

    def compile_all(self, *policy_files: str ):
        for entity in self.read_entities(*policy_files):
            self.compile_entity(entity)

if __name__ == "__main__":
    p = PolicyCompiler()
    p.compile_all(*['demo/testrole1_policy.json'])
# utilities for parsing AWS Resource Names

# parses an ARN and returns the constituent parts

from dataclasses import dataclass
from typing import Optional

PARTITIONS = set(['aws', 'aws-cn', 'aws-us-gov'])

@dataclass
class ARN:
    partition: str
    service: str
    region: str
    account_id: str
    resource_type: Optional[str]
    resource_id: str

    @staticmethod
    def parse(raw: str):
        parts = raw.split(':')
        if parts[0] != 'arn':
            raise ValueError(f"invalid arn: {raw}")
        
        if parts[1] in PARTITIONS:
            partition = parts[1]
        else:
            raise ValueError(f"invalid partition: parts[1]")
        
        service, region, account_id = parts[2], parts[3], parts[4]
        rest = parts[5:]
        if len(rest) == 1:
            (res_type, res_id) = ARN.try_parse_resource_type(parts[5])
        else:
            res_type, res_id = parts[5], parts[6]

        
        return ARN(partition, service, region, account_id, res_type, res_id)
    
    #arn:partition:service:region:account-id:resource-type/resource-id
    #arn:partition:service:region:account-id:resource-type:resource-id
    @staticmethod
    def try_parse_resource_type(arn_segment):
        segment_parts = arn_segment.split('/')
        res_type = res_id = None
        if len(segment_parts) > 1:
            res_type = segment_parts[0]
            res_id = '/'.join(segment_parts[1:])
        else:
            res_id = arn_segment
        
        return res_type, res_id
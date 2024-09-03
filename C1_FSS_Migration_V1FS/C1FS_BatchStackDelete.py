import boto3
from botocore.exceptions import ClientError
import pandas as pd

parameter_key = "FSSBucketName" # Stack Parameter Key use for Filter Stacks  Ex: "FSSBucketName"
parameter_value = "file-storage-security" # Stack Parameter Value use for Filter Stacks Ex: "file-storage-security"
regions=["us-east-1", "us-east-2"]

def deleteStacks():
    try:
        for region in regions:
            print(f"Filter stacks with parameter {parameter_key}={parameter_value} in region {region}")
            cf_client_assumed = boto3.client(
                'cloudformation',
                region_name=region
            )
            stacks = cf_client_assumed.describe_stacks()
            df_stacks = pd.json_normalize(stacks['Stacks'])
            filtered_stacks = df_stacks[df_stacks['Parameters'].apply(
                lambda params: isinstance(params, list) and any(
                    param['ParameterKey'] == parameter_key and param['ParameterValue'] == parameter_value
                    for param in params
                )
            )]

            if len(filtered_stacks) == 0:
                print("No stacks found")
                continue
            else:
                for index, row in filtered_stacks.iterrows():
                    stack_id = row["StackId"]
                    try:
                        cf_client_assumed.delete_stack(StackName=stack_id)
                        print(f"Stack deletion initiated {stack_id}")
                        try:
                            cf_client_assumed.describe_stacks(StackName=stack_id)['Stacks'][0]['StackStatus']
                        except Exception as e:
                            if 'does not exist' in str(e):
                                print(f"Stack {stack_id} don't exist")
                                break
                    except Exception as e:
                        print(f"ERROR: Delete action failed {stack_id}: {e}")
    except Exception as e:
        print(f"ERROR: {e}")

deleteStacks()
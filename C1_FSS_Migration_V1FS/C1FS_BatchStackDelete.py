import boto3
from botocore.exceptions import ClientError
import pandas as pd
import argparse

def delete_stacks(parameter_key, parameter_value, regions):
    try:
        for region in regions:
            print(f"Filtering stacks with parameter {parameter_key}={parameter_value} in region {region}")
            cf_client_assumed = boto3.client('cloudformation', region_name=region)
            stacks = cf_client_assumed.describe_stacks()
            df_stacks = pd.json_normalize(stacks['Stacks'])
            
            filtered_stacks = df_stacks[df_stacks['Parameters'].apply(
                lambda params: isinstance(params, list) and any(
                    param['ParameterKey'] == parameter_key and param['ParameterValue'] == parameter_value
                    for param in params
                )
            )]

            if len(filtered_stacks) == 0:
                print(f"No stacks found in region {region}")
                continue
            else:
                for index, row in filtered_stacks.iterrows():
                    stack_id = row["StackId"]
                    try:
                        cf_client_assumed.delete_stack(StackName=stack_id)
                        print(f"Stack deletion initiated for {stack_id} in region {region}")
                        try:
                            cf_client_assumed.describe_stacks(StackName=stack_id)['Stacks'][0]['StackStatus']
                        except Exception as e:
                            if 'does not exist' in str(e):
                                print(f"Stack {stack_id} no longer exists")
                                break
                    except Exception as e:
                        print(f"ERROR: Failed to delete stack {stack_id}: {e}")
    except Exception as e:
        print(f"ERROR: {e}")

def main():
    parser = argparse.ArgumentParser(description='Delete CloudFormation stacks filtered by a specific parameter key and value in multiple regions.')
    parser.add_argument('--parameter-key', type=str, required=True, help='The CloudFormation stack parameter key to filter by.')
    parser.add_argument('--parameter-value', type=str, required=True, help='The CloudFormation stack parameter value to filter by.')
    parser.add_argument('--regions', type=str, nargs='+', required=True, help='The AWS regions where the stacks are located.')

    args = parser.parse_args()

    delete_stacks(args.parameter_key, args.parameter_value, args.regions)

if __name__ == "__main__":
    main()
import boto3

bucket_name = "yessenia-bucket-test-tm"

s3 = boto3.client("s3")

response = s3.list_objects_v2(Bucket=bucket_name)

if "Contents" in response:
    for obj in response["Contents"]:
        print(obj["Key"], obj["Size"])
else:
    print("No objects found")
# Migration from Cloud One File Storage Security (C1FSS) to Vision One File Security (V1FS)

This guide outlines the steps required to successfully migrate from Trend Micro Cloud One File Storage Security to Vision One File Security.

## Steps to Migrate

1. **Clone the Repository**
   - Begin by cloning the repository that contains the migration script:
     ```sh
     git clone https://github.com/XeniaP/Utils_AWS.git
     cd Utils_AWS/C1_FSS_Migration_V1FS
     ```

2. **Set Up Python Environment**
   - Ensure you have Python installed. It's recommended to create a virtual environment to manage dependencies:
     ```sh
     python3 -m venv venv
     source venv/bin/activate  # On Windows use `venv\Scripts\activate`
     ```

3. **Install Dependencies**
   - Install the required Python packages using the `requirements.txt` file provided:
     ```sh
     pip install -r requirements.txt
     ```

4. **Activate File Security in All Accounts**
   - Ensure that File Security is enabled across all relevant accounts to provide protection and monitoring for your file storage.

5. **Enable Scanners in Specific Regions**
   - Identify and enable scanners in the regions where they are needed to ensure comprehensive coverage and compliance with regional data security requirements.

6. **Configure Monitoring on the Necessary Buckets**
   - Set up monitoring for specific buckets that require continuous security scanning and threat detection.

7. **Remove Stacks from Cloud One Deployment**
   - Decommission and remove the existing Cloud One stacks that were used for File Storage Security as they will no longer be necessary after migration.
   - To facilitate this process, you can use the modified script, which now accepts parameters to specify the region and stack name prefix.

   ### Using the Script

   1. **AWS Credentials Configuration**:
      - Before running the script, ensure that your AWS credentials are properly configured. You can do this by setting up the credentials in the `~/.aws/credentials` file or by exporting the credentials as environment variables:
        ```sh
        export AWS_ACCESS_KEY_ID=your_access_key_id
        export AWS_SECRET_ACCESS_KEY=your_secret_access_key
        export AWS_SESSION_TOKEN=your_session_token (if applicable)
        ```

   2. **Running the Script**:
      - Execute the script with the required parameters to delete the stacks. You can specify the region and stack name prefix directly from the command line:
        ```sh
        python C1FS_BatchStackDelete.py --parameter-key FSSBucketName --parameter-value file-storage-security --regions us-east-1 us-east-2
        ```

      - The script will iterate through the specified region and delete all stacks that start with the given prefix. The progress and results will be logged to the console.

   3. **Validation**:
      - After running the script, it's recommended to manually check the AWS CloudFormation console or use the AWS CLI to ensure that all targeted stacks have been successfully deleted:
        ```sh
        aws cloudformation describe-stacks --region us-east-1 --stack-name C1FSS-Example-Stack
        ```

5. **Validate Scan Results**
   - After the migration, perform thorough validation of scan results to ensure that the new Vision One File Security setup is functioning correctly and covering all required assets.

## Additional Notes
- Ensure that all changes are documented and approved by your compliance team.
- It is recommended to perform the migration during a maintenance window to minimize any potential impact on production environments.


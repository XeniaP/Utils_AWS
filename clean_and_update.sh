#!/bin/bash
# =============================================================================
# cleanup_and_update.sh
# Limpia recursos huérfanos de CloudFormation y dispara el update del stack
# en múltiples cuentas via AssumeRole desde una cuenta central.
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURACIÓN — editar antes de ejecutar
# =============================================================================

ROLE_NAME="OrganizationAccountAccessRole"   # Nombre del role a asumir en cada cuenta
REGION="us-east-1"                           # Región donde están los recursos
STACK_NAME_PREFIX="VisionOneSecurityApplicationsStack"  # Busca el stack que empiece con este prefijo
ECR_REPO="trendmicro-container-security-aws-security-manager"
IAM_ROLE="trendmicro-container-security-verify-ecr-replication-role"
TEMPLATE_URL=""  # Dejar vacío para usar el template ya asociado al stack (continue-update-rollback)
                 # Si quieres pasar un template S3: "https://s3.amazonaws.com/bucket/template.yaml"

# Lista de cuentas destino — agregar todas las que correspondan
ACCOUNTS=(
  "136191772539"
  "586794439760"
  # ... agregar el resto
)

# =============================================================================
# COLORES para output
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC}  [$1] $2"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    [$1] $2"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  [$1] $2"; }
log_error()   { echo -e "${RED}[ERROR]${NC} [$1] $2"; }

# =============================================================================
# FUNCIÓN: asumir role en una cuenta y exportar credenciales temporales
# =============================================================================
assume_role() {
  local account_id=$1
  local role_arn="arn:aws:iam::${account_id}:role/${ROLE_NAME}"

  log_info "$account_id" "Asumiendo role: $role_arn"

  local creds
  creds=$(aws sts assume-role \
    --role-arn "$role_arn" \
    --role-session-name "cleanup-session-${account_id}" \
    --query "Credentials" \
    --output json 2>&1) || {
      log_error "$account_id" "No se pudo asumir el role: $creds"
      return 1
    }

  export AWS_ACCESS_KEY_ID=$(echo "$creds"     | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKeyId'])")
  export AWS_SECRET_ACCESS_KEY=$(echo "$creds" | python3 -c "import sys,json; print(json.load(sys.stdin)['SecretAccessKey'])")
  export AWS_SESSION_TOKEN=$(echo "$creds"     | python3 -c "import sys,json; print(json.load(sys.stdin)['SessionToken'])")

  log_ok "$account_id" "Role asumido correctamente"
}

# =============================================================================
# FUNCIÓN: limpiar credenciales temporales
# =============================================================================
clear_credentials() {
  unset AWS_ACCESS_KEY_ID
  unset AWS_SECRET_ACCESS_KEY
  unset AWS_SESSION_TOKEN
}

# =============================================================================
# FUNCIÓN: limpiar el IAM Role huérfano
# =============================================================================
cleanup_iam_role() {
  local account_id=$1

  # Verificar si existe
  if ! aws iam get-role --role-name "$IAM_ROLE" --region "$REGION" &>/dev/null; then
    log_warn "$account_id" "IAM Role '$IAM_ROLE' no existe, saltando..."
    return 0
  fi

  log_info "$account_id" "Limpiando IAM Role: $IAM_ROLE"

  # Desatachar políticas managed
  local managed_policies
  managed_policies=$(aws iam list-attached-role-policies \
    --role-name "$IAM_ROLE" \
    --query "AttachedPolicies[].PolicyArn" \
    --output text 2>/dev/null || echo "")

  for policy_arn in $managed_policies; do
    log_info "$account_id" "  Detaching managed policy: $policy_arn"
    aws iam detach-role-policy \
      --role-name "$IAM_ROLE" \
      --policy-arn "$policy_arn"
  done

  # Eliminar políticas inline
  local inline_policies
  inline_policies=$(aws iam list-role-policies \
    --role-name "$IAM_ROLE" \
    --query "PolicyNames[]" \
    --output text 2>/dev/null || echo "")

  for policy_name in $inline_policies; do
    log_info "$account_id" "  Deleting inline policy: $policy_name"
    aws iam delete-role-policy \
      --role-name "$IAM_ROLE" \
      --policy-name "$policy_name"
  done

  # Eliminar el role
  aws iam delete-role --role-name "$IAM_ROLE"
  log_ok "$account_id" "IAM Role eliminado"
}

# =============================================================================
# FUNCIÓN: limpiar el ECR repo huérfano
# =============================================================================
cleanup_ecr_repo() {
  local account_id=$1

  # Verificar si existe
  if ! aws ecr describe-repositories \
    --repository-names "$ECR_REPO" \
    --region "$REGION" &>/dev/null; then
    log_warn "$account_id" "ECR repo '$ECR_REPO' no existe, saltando..."
    return 0
  fi

  log_info "$account_id" "Eliminando ECR repo: $ECR_REPO"
  aws ecr delete-repository \
    --repository-name "$ECR_REPO" \
    --region "$REGION" \
    --force

  log_ok "$account_id" "ECR repo eliminado"
}

# =============================================================================
# DOCUMENTOS DE LAS 4 POLÍTICAS — tomados del template de CloudFormation
# =============================================================================

POLICY1_DOCUMENT='{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid":"AllowLogsAll","Effect":"Allow","Action":["logs:*"],"Resource":"*"},
    {"Sid":"AllowCloudFormationRead","Effect":"Allow","Action":["cloudformation:Describe*","cloudformation:Get*","cloudformation:List*"],"Resource":"*"},
    {"Sid":"AllowCloudFormationWriteByName","Effect":"Allow","Action":["cloudformation:Create*","cloudformation:Update*","cloudformation:ExecuteChangeSet","cloudformation:SetStackPolicy","cloudformation:TagResource"],"Resource":["arn:aws:cloudformation:*:*:stack/*VisionOne*/*","arn:aws:cloudformation:*:*:stack/*Vision-One*/*","arn:aws:cloudformation:*:*:stack/*V1*/*","arn:aws:cloudformation:*:*:stack/*v1*/*","arn:aws:cloudformation:*:*:stack/*tmv1*/*","arn:aws:cloudformation:*:*:stack/*RealTimePostureMonitoring*/*","arn:aws:cloudformation:*:*:stack/*cloud-audit-log-monitoring*/*","arn:aws:cloudformation:*:*:stack/*CAM*/*","arn:aws:cloudformation:*:*:stack/*dspm*/*","arn:aws:cloudformation:*:*:stack/*DSPM*/*","arn:aws:cloudformation:*:*:stackset/*VisionOne*:*","arn:aws:cloudformation:*:*:stackset/*Vision-One*:*","arn:aws:cloudformation:*:*:stackset/*V1*:*","arn:aws:cloudformation:*:*:stackset/*v1*:*","arn:aws:cloudformation:*:*:stackset/*tmv1*:*","arn:aws:cloudformation:*:*:stackset/*RealTimePostureMonitoring*:*","arn:aws:cloudformation:*:*:stackset/*cloud-audit-log-monitoring*:*","arn:aws:cloudformation:*:*:stackset/*CAM*:*","arn:aws:cloudformation:*:*:stackset/*dspm*:*","arn:aws:cloudformation:*:*:stackset/*DSPM*:*","arn:aws:cloudformation:*:*:changeSet/*VisionOne*/*","arn:aws:cloudformation:*:*:changeSet/*Vision-One*/*","arn:aws:cloudformation:*:*:changeSet/*V1*/*","arn:aws:cloudformation:*:*:changeSet/*v1*/*","arn:aws:cloudformation:*:*:changeSet/*tmv1*/*","arn:aws:cloudformation:*:*:changeSet/*RealTimePostureMonitoring*/*","arn:aws:cloudformation:*:*:changeSet/*cloud-audit-log-monitoring*/*","arn:aws:cloudformation:*:*:changeSet/*CAM*/*","arn:aws:cloudformation:*:*:changeSet/*dspm*/*","arn:aws:cloudformation:*:*:changeSet/*DSPM*/*"]},
    {"Sid":"AllowCloudFormationDeleteByTag","Effect":"Allow","Action":["cloudformation:Delete*","cloudformation:ListStacks","cloudformation:UntagResource"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowCloudFormationDeleteByName","Effect":"Allow","Action":["cloudformation:Delete*","cloudformation:ListStacks","cloudformation:UntagResource"],"Resource":["arn:aws:cloudformation:*:*:stack/*VisionOne*/*","arn:aws:cloudformation:*:*:stack/*Vision-One*/*","arn:aws:cloudformation:*:*:stack/*V1*/*","arn:aws:cloudformation:*:*:stack/*v1*/*","arn:aws:cloudformation:*:*:stack/*tmv1*/*","arn:aws:cloudformation:*:*:stack/*RealTimePostureMonitoring*/*","arn:aws:cloudformation:*:*:stack/*cloud-audit-log-monitoring*/*","arn:aws:cloudformation:*:*:stack/*CAM*/*","arn:aws:cloudformation:*:*:stack/*dspm*/*","arn:aws:cloudformation:*:*:stack/*DSPM*/*","arn:aws:cloudformation:*:*:stackset/*VisionOne*:*","arn:aws:cloudformation:*:*:stackset/*Vision-One*:*","arn:aws:cloudformation:*:*:stackset/*V1*:*","arn:aws:cloudformation:*:*:stackset/*v1*:*","arn:aws:cloudformation:*:*:stackset/*tmv1*:*","arn:aws:cloudformation:*:*:stackset/*RealTimePostureMonitoring*:*","arn:aws:cloudformation:*:*:stackset/*cloud-audit-log-monitoring*:*","arn:aws:cloudformation:*:*:stackset/*CAM*:*","arn:aws:cloudformation:*:*:stackset/*dspm*:*","arn:aws:cloudformation:*:*:stackset/*DSPM*:*","arn:aws:cloudformation:*:*:changeSet/*VisionOne*/*","arn:aws:cloudformation:*:*:changeSet/*Vision-One*/*","arn:aws:cloudformation:*:*:changeSet/*V1*/*","arn:aws:cloudformation:*:*:changeSet/*v1*/*","arn:aws:cloudformation:*:*:changeSet/*tmv1*/*","arn:aws:cloudformation:*:*:changeSet/*RealTimePostureMonitoring*/*","arn:aws:cloudformation:*:*:changeSet/*cloud-audit-log-monitoring*/*","arn:aws:cloudformation:*:*:changeSet/*CAM*/*","arn:aws:cloudformation:*:*:changeSet/*dspm*/*","arn:aws:cloudformation:*:*:changeSet/*DSPM*/*"]},
    {"Sid":"AllowIAMCreate","Effect":"Allow","Action":["iam:Create*","iam:PutRolePolicy","iam:AttachRolePolicy","iam:PassRole","iam:Add*"],"Resource":"*"},
    {"Sid":"AllowIAMRead","Effect":"Allow","Action":["iam:Get*","iam:List*"],"Resource":"*"},
    {"Sid":"AllowIAMModifyByName","Effect":"Allow","Action":["iam:Delete*","iam:DetachRolePolicy","iam:Untag*","iam:Tag*","iam:Remove*","iam:Update*"],"Resource":["arn:aws:iam::*:role/*VisionOne*","arn:aws:iam::*:role/*Vision-One*","arn:aws:iam::*:role/*V1*","arn:aws:iam::*:role/*v1*","arn:aws:iam::*:role/*tmv1*","arn:aws:iam::*:role/*RealTimePostureMonitoring*","arn:aws:iam::*:role/*cloud-audit-log-monitoring*","arn:aws:iam::*:role/*CAM*","arn:aws:iam::*:role/*dspm*","arn:aws:iam::*:role/*DSPM*","arn:aws:iam::*:policy/*VisionOne*","arn:aws:iam::*:policy/*Vision-One*","arn:aws:iam::*:policy/*V1*","arn:aws:iam::*:policy/*v1*","arn:aws:iam::*:policy/*tmv1*","arn:aws:iam::*:policy/*RealTimePostureMonitoring*","arn:aws:iam::*:policy/*cloud-audit-log-monitoring*","arn:aws:iam::*:policy/*CAM*","arn:aws:iam::*:policy/*dspm*","arn:aws:iam::*:policy/*DSPM*","arn:aws:iam::*:instance-profile/*VisionOne*","arn:aws:iam::*:instance-profile/*Vision-One*","arn:aws:iam::*:instance-profile/*V1*","arn:aws:iam::*:instance-profile/*v1*","arn:aws:iam::*:instance-profile/*tmv1*","arn:aws:iam::*:instance-profile/*RealTimePostureMonitoring*","arn:aws:iam::*:instance-profile/*cloud-audit-log-monitoring*","arn:aws:iam::*:instance-profile/*CAM*","arn:aws:iam::*:instance-profile/*dspm*","arn:aws:iam::*:instance-profile/*DSPM*"]},
    {"Sid":"AllowIAMModifyByTag","Effect":"Allow","Action":["iam:Delete*","iam:DetachRolePolicy","iam:Untag*","iam:Tag*","iam:Remove*","iam:Update*"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"}
  ]
}'

POLICY2_DOCUMENT='{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid":"AllowLambdaCreate","Effect":"Allow","Action":["lambda:CreateFunction","lambda:AddPermission","lambda:InvokeFunction","lambda:CreateAlias"],"Resource":"*"},
    {"Sid":"AllowLambdaRead","Effect":"Allow","Action":["lambda:Get*","lambda:List*"],"Resource":"*"},
    {"Sid":"AllowLambdaModifyByName","Effect":"Allow","Action":["lambda:UpdateFunction*","lambda:DeleteFunction","lambda:RemovePermission","lambda:UpdateAlias","lambda:DeleteAlias","lambda:UntagResource","lambda:TagResource"],"Resource":["arn:aws:lambda:*:*:function:*VisionOne*","arn:aws:lambda:*:*:function:*Vision-One*","arn:aws:lambda:*:*:function:*V1*","arn:aws:lambda:*:*:function:*v1*","arn:aws:lambda:*:*:function:*tmv1*","arn:aws:lambda:*:*:function:*RealTimePostureMonitoring*","arn:aws:lambda:*:*:function:*cloud-audit-log-monitoring*","arn:aws:lambda:*:*:function:*CAM*","arn:aws:lambda:*:*:function:*dspm*","arn:aws:lambda:*:*:function:*DSPM*"]},
    {"Sid":"AllowLambdaModifyByTag","Effect":"Allow","Action":["lambda:UpdateFunction*","lambda:DeleteFunction","lambda:RemovePermission","lambda:UpdateAlias","lambda:DeleteAlias","lambda:UntagResource","lambda:TagResource"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowSecretsCreate","Effect":"Allow","Action":["secretsmanager:CreateSecret","secretsmanager:PutSecretValue","secretsmanager:ReplicateSecretToRegions"],"Resource":"*"},
    {"Sid":"AllowSecretsReadByTag","Effect":"Allow","Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowSecretsReadByName","Effect":"Allow","Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],"Resource":["arn:aws:secretsmanager:*:*:secret:/V1CS/*","arn:aws:secretsmanager:*:*:secret:*VisionOne*","arn:aws:secretsmanager:*:*:secret:*Vision-One*","arn:aws:secretsmanager:*:*:secret:*V1*","arn:aws:secretsmanager:*:*:secret:*v1*","arn:aws:secretsmanager:*:*:secret:*tmv1*","arn:aws:secretsmanager:*:*:secret:*RealTimePostureMonitoring*","arn:aws:secretsmanager:*:*:secret:*cloud-audit-log-monitoring*","arn:aws:secretsmanager:*:*:secret:*CAM*","arn:aws:secretsmanager:*:*:secret:*dspm*","arn:aws:secretsmanager:*:*:secret:*DSPM*"]},
    {"Sid":"AllowSecretsModifyByName","Effect":"Allow","Action":["secretsmanager:UpdateSecret","secretsmanager:DeleteSecret","secretsmanager:CancelRotateSecret","secretsmanager:RotateSecret","secretsmanager:UntagResource","secretsmanager:TagResource"],"Resource":["arn:aws:secretsmanager:*:*:secret:/V1CS/*","arn:aws:secretsmanager:*:*:secret:*VisionOne*","arn:aws:secretsmanager:*:*:secret:*Vision-One*","arn:aws:secretsmanager:*:*:secret:*V1*","arn:aws:secretsmanager:*:*:secret:*v1*","arn:aws:secretsmanager:*:*:secret:*tmv1*","arn:aws:secretsmanager:*:*:secret:*RealTimePostureMonitoring*","arn:aws:secretsmanager:*:*:secret:*cloud-audit-log-monitoring*","arn:aws:secretsmanager:*:*:secret:*CAM*","arn:aws:secretsmanager:*:*:secret:*dspm*","arn:aws:secretsmanager:*:*:secret:*DSPM*"]},
    {"Sid":"AllowSecretsModifyByTag","Effect":"Allow","Action":["secretsmanager:UpdateSecret","secretsmanager:DeleteSecret","secretsmanager:CancelRotateSecret","secretsmanager:RotateSecret","secretsmanager:UntagResource","secretsmanager:TagResource"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowEventBridgeCreate","Effect":"Allow","Action":["events:PutRule","events:PutTargets"],"Resource":"*"},
    {"Sid":"AllowEventBridgeModifyByName","Effect":"Allow","Action":["events:DescribeRule","events:DeleteRule","events:RemoveTargets","events:UntagResource","events:TagResource"],"Resource":["arn:aws:events:*:*:rule/*Vision-One*","arn:aws:events:*:*:rule/*VisionOne*","arn:aws:events:*:*:rule/*vision-one*","arn:aws:events:*:*:rule/*TrendMicro*","arn:aws:events:*:*:rule/*V1*","arn:aws:events:*:*:rule/*v1*","arn:aws:events:*:*:rule/*tmv1*","arn:aws:events:*:*:rule/*RealTimePostureMonitoring*","arn:aws:events:*:*:rule/*cloud-audit-log-monitoring*","arn:aws:events:*:*:rule/*CAM*","arn:aws:events:*:*:rule/*dspm*","arn:aws:events:*:*:rule/*DSPM*"]},
    {"Sid":"AllowEventBridgeModifyByTag","Effect":"Allow","Action":["events:DescribeRule","events:DeleteRule","events:RemoveTargets","events:UntagResource","events:TagResource"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"}
  ]
}'

POLICY3_DOCUMENT='{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid":"AllowSchedulerCreate","Effect":"Allow","Action":["scheduler:CreateSchedule","scheduler:CreateScheduleGroup","scheduler:ListSchedules"],"Resource":"*"},
    {"Sid":"AllowSchedulerModifyByName","Effect":"Allow","Action":["scheduler:UpdateSchedule","scheduler:DeleteSchedule","scheduler:DeleteScheduleGroup","scheduler:UntagResource","scheduler:TagResource"],"Resource":["arn:aws:scheduler:*:*:schedule/*/*Vision-One*","arn:aws:scheduler:*:*:schedule/*/*VisionOne*","arn:aws:scheduler:*:*:schedule/*/*vision-one*","arn:aws:scheduler:*:*:schedule-group/*Vision-One*","arn:aws:scheduler:*:*:schedule-group/*VisionOne*","arn:aws:scheduler:*:*:schedule-group/*vision-one*","arn:aws:scheduler:*:*:schedule/*/*V1*","arn:aws:scheduler:*:*:schedule/*/*v1*","arn:aws:scheduler:*:*:schedule/*/*tmv1*","arn:aws:scheduler:*:*:schedule/*/*RealTimePostureMonitoring*","arn:aws:scheduler:*:*:schedule/*/*cloud-audit-log-monitoring*","arn:aws:scheduler:*:*:schedule/*/*CAM*","arn:aws:scheduler:*:*:schedule/*/*dspm*","arn:aws:scheduler:*:*:schedule/*/*DSPM*","arn:aws:scheduler:*:*:schedule-group/*V1*","arn:aws:scheduler:*:*:schedule-group/*v1*","arn:aws:scheduler:*:*:schedule-group/*tmv1*","arn:aws:scheduler:*:*:schedule-group/*RealTimePostureMonitoring*","arn:aws:scheduler:*:*:schedule-group/*cloud-audit-log-monitoring*","arn:aws:scheduler:*:*:schedule-group/*CAM*","arn:aws:scheduler:*:*:schedule-group/*dspm*","arn:aws:scheduler:*:*:schedule-group/*DSPM*"]},
    {"Sid":"AllowSchedulerModifyByTag","Effect":"Allow","Action":["scheduler:UpdateSchedule","scheduler:DeleteSchedule","scheduler:DeleteScheduleGroup","scheduler:UntagResource","scheduler:TagResource"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowS3Create","Effect":"Allow","Action":["s3:CreateBucket","s3:Put*","s3:AbortMultipartUpload"],"Resource":"*"},
    {"Sid":"AllowS3Read","Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"},
    {"Sid":"AllowS3DeleteByTag","Effect":"Allow","Action":["s3:DeleteBucket"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowS3DeleteByName","Effect":"Allow","Action":["s3:DeleteBucket"],"Resource":["arn:aws:s3:::*vision-one*","arn:aws:s3:::*vision-one*/*","arn:aws:s3:::*visionone*","arn:aws:s3:::*visionone*/*","arn:aws:s3:::*trendmicro*","arn:aws:s3:::*trendmicro*/*","arn:aws:s3:::*v1*","arn:aws:s3:::*v1*/*","arn:aws:s3:::*tmv1*","arn:aws:s3:::*tmv1*/*","arn:aws:s3:::*realtimeposturemonitoring*","arn:aws:s3:::*realtimeposturemonitoring*/*","arn:aws:s3:::*cloud-audit-log-monitoring*","arn:aws:s3:::*cloud-audit-log-monitoring*/*","arn:aws:s3:::*cam*","arn:aws:s3:::*cam*/*","arn:aws:s3:::*dspm*","arn:aws:s3:::*dspm*/*"]},
    {"Sid":"AllowSQSCreate","Effect":"Allow","Action":["sqs:CreateQueue","sqs:SetQueueAttributes","sqs:AddPermission"],"Resource":"*"},
    {"Sid":"AllowSQSRead","Effect":"Allow","Action":["sqs:GetQueue*"],"Resource":"*"},
    {"Sid":"AllowSQSModifyByName","Effect":"Allow","Action":["sqs:DeleteQueue","sqs:DeleteMessage","sqs:UntagQueue","sqs:TagQueue"],"Resource":["arn:aws:sqs:*:*:*Vision-One*","arn:aws:sqs:*:*:*VisionOne*","arn:aws:sqs:*:*:*vision-one*","arn:aws:sqs:*:*:*visionone*","arn:aws:sqs:*:*:*TrendMicro*","arn:aws:sqs:*:*:*trendmicro*","arn:aws:sqs:*:*:*V1*","arn:aws:sqs:*:*:*v1*","arn:aws:sqs:*:*:*tmv1*","arn:aws:sqs:*:*:*RealTimePostureMonitoring*","arn:aws:sqs:*:*:*cloud-audit-log-monitoring*","arn:aws:sqs:*:*:*CAM*","arn:aws:sqs:*:*:*dspm*","arn:aws:sqs:*:*:*DSPM*"]},
    {"Sid":"AllowSQSModifyByTag","Effect":"Allow","Action":["sqs:DeleteQueue","sqs:DeleteMessage","sqs:UntagQueue","sqs:TagQueue"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowSSMCreate","Effect":"Allow","Action":["ssm:PutParameter"],"Resource":"*"},
    {"Sid":"AllowSSMRead","Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters"],"Resource":"*"},
    {"Sid":"AllowSSMDeleteByTag","Effect":"Allow","Action":["ssm:DeleteParameter","ssm:RemoveTagsFromResource"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowSSMModifyByName","Effect":"Allow","Action":["ssm:DeleteParameter","ssm:RemoveTagsFromResource","ssm:AddTagsToResource"],"Resource":["arn:aws:ssm:*:*:parameter/*Vision-One*","arn:aws:ssm:*:*:parameter/*VisionOne*","arn:aws:ssm:*:*:parameter/*vision-one*","arn:aws:ssm:*:*:parameter/*TrendMicro*","arn:aws:ssm:*:*:parameter/*trendmicro*","arn:aws:ssm:*:*:parameter/*V1*","arn:aws:ssm:*:*:parameter/*v1*","arn:aws:ssm:*:*:parameter/*tmv1*","arn:aws:ssm:*:*:parameter/*RealTimePostureMonitoring*","arn:aws:ssm:*:*:parameter/*cloud-audit-log-monitoring*","arn:aws:ssm:*:*:parameter/*CAM*","arn:aws:ssm:*:*:parameter/*dspm*","arn:aws:ssm:*:*:parameter/*DSPM*"]}
  ]
}'

POLICY4_DOCUMENT='{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid":"AllowEC2SnapshotRead","Effect":"Allow","Action":["ec2:CreateSnapshot","ec2:DescribeSnapshots","ec2:DescribeVolumes","ec2:DescribeInstances","ec2:DescribeImages"],"Resource":"*"},
    {"Sid":"AllowEC2SnapshotDeleteByTag","Effect":"Allow","Action":["ec2:DeleteSnapshot","ec2:DeleteTags"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowEC2SnapshotDeleteByName","Effect":"Allow","Action":["ec2:DeleteSnapshot","ec2:DeleteTags"],"Condition":{"StringLike":{"aws:ResourceTag/Name":["*VisionOne*","*Vision-One*","*TrendMicro*","*V1*","*v1*","*tmv1*","*RealTimePostureMonitoring*","*cloud-audit-log-monitoring*","*CAM*","*dspm*","*DSPM*"]}},"Resource":["arn:aws:ec2:*:*:snapshot/*","arn:aws:ec2:*:*:volume/*"]},
    {"Sid":"AllowEC2SnapshotTagByName","Effect":"Allow","Action":["ec2:CreateTags"],"Condition":{"StringLike":{"aws:RequestTag/Name":["*VisionOne*","*Vision-One*","*TrendMicro*","*V1*","*v1*","*tmv1*","*RealTimePostureMonitoring*","*cloud-audit-log-monitoring*","*CAM*","*dspm*","*DSPM*"]}},"Resource":["arn:aws:ec2:*:*:snapshot/*","arn:aws:ec2:*:*:volume/*","arn:aws:ec2:*:*:instance/*"]},
    {"Sid":"AllowStepFunctionsCreate","Effect":"Allow","Action":["states:CreateStateMachine"],"Resource":"*"},
    {"Sid":"AllowStepFunctionsModifyByTag","Effect":"Allow","Action":["states:DeleteStateMachine","states:UntagResource","states:TagResource"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowStepFunctionsModifyByName","Effect":"Allow","Action":["states:DeleteStateMachine","states:UntagResource","states:TagResource"],"Resource":["arn:aws:states:*:*:stateMachine:*Vision-One*","arn:aws:states:*:*:stateMachine:*VisionOne*","arn:aws:states:*:*:stateMachine:*vision-one*","arn:aws:states:*:*:stateMachine:*TrendMicro*","arn:aws:states:*:*:stateMachine:*V1*","arn:aws:states:*:*:stateMachine:*v1*","arn:aws:states:*:*:stateMachine:*tmv1*","arn:aws:states:*:*:stateMachine:*RealTimePostureMonitoring*","arn:aws:states:*:*:stateMachine:*cloud-audit-log-monitoring*","arn:aws:states:*:*:stateMachine:*CAM*","arn:aws:states:*:*:stateMachine:*dspm*","arn:aws:states:*:*:stateMachine:*DSPM*"]},
    {"Sid":"AllowAppConfigAll","Effect":"Allow","Action":["appconfig:*"],"Resource":"*"},
    {"Sid":"AllowECRReplication","Effect":"Allow","Action":["ecr:DescribeRegistry","ecr:PutReplicationConfiguration","ecr:DeleteReplicationConfiguration"],"Resource":"*"},
    {"Sid":"AllowECRCreate","Effect":"Allow","Action":["ecr:CreateRepository","ecr:DescribeRepositories","ecr:PutLifecyclePolicy","ecr:SetRepositoryPolicy","ecr:GetRepositoryPolicy"],"Resource":"*"},
    {"Sid":"AllowECRModifyByTag","Effect":"Allow","Action":["ecr:DeleteRepository","ecr:UntagResource","ecr:TagResource"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowECRModifyByName","Effect":"Allow","Action":["ecr:DeleteRepository","ecr:UntagResource","ecr:TagResource"],"Resource":["arn:aws:ecr:*:*:repository/*trendmicro*","arn:aws:ecr:*:*:repository/*vision-one*","arn:aws:ecr:*:*:repository/*VisionOne*","arn:aws:ecr:*:*:repository/*v1*","arn:aws:ecr:*:*:repository/*tmv1*","arn:aws:ecr:*:*:repository/*RealTimePostureMonitoring*","arn:aws:ecr:*:*:repository/*cloud-audit-log-monitoring*","arn:aws:ecr:*:*:repository/*CAM*","arn:aws:ecr:*:*:repository/*dspm*","arn:aws:ecr:*:*:repository/*DSPM*"]},
    {"Sid":"AllowCodeBuildCreate","Effect":"Allow","Action":["codebuild:CreateProject","codebuild:BatchGetProjects"],"Resource":"*"},
    {"Sid":"AllowCodeBuildModifyByTag","Effect":"Allow","Action":["codebuild:UpdateProject","codebuild:DeleteProject"],"Condition":{"Null":{"aws:ResourceTag/TrendMicroProduct":"false"}},"Resource":"*"},
    {"Sid":"AllowCodeBuildModifyByName","Effect":"Allow","Action":["codebuild:UpdateProject","codebuild:DeleteProject"],"Resource":["arn:aws:codebuild:*:*:project/*trendmicro*","arn:aws:codebuild:*:*:project/*vision-one*","arn:aws:codebuild:*:*:project/*VisionOne*","arn:aws:codebuild:*:*:project/*Vision-One*","arn:aws:codebuild:*:*:project/*v1*","arn:aws:codebuild:*:*:project/*tmv1*","arn:aws:codebuild:*:*:project/*RealTimePostureMonitoring*","arn:aws:codebuild:*:*:project/*cloud-audit-log-monitoring*","arn:aws:codebuild:*:*:project/*CAM*","arn:aws:codebuild:*:*:project/*dspm*","arn:aws:codebuild:*:*:project/*DSPM*"]}
  ]
}'

LAMBDA_ROLE_PREFIX="StackSet-VisionOneStackSe-CreateFeaturesStackLambda"

# =============================================================================
# FUNCIÓN: resolver el nombre del role Lambda buscando por prefijo
# =============================================================================
resolve_lambda_role() {
  local role_name
  role_name=$(aws iam list-roles \
    --query "Roles[?starts_with(RoleName, '${LAMBDA_ROLE_PREFIX}')].RoleName | [0]" \
    --output text 2>/dev/null || echo "None")

  if [ "$role_name" == "None" ] || [ -z "$role_name" ]; then
    echo ""
  else
    echo "$role_name"
  fi
}

# =============================================================================
# FUNCIÓN: crear o actualizar una política IAM directamente via AWS CLI
# (replica la lógica de la Lambda IAMPolicyCreator sin invocarla)
# =============================================================================
create_or_update_policy() {
  local account_id=$1
  local policy_name=$2
  local policy_document=$3
  local role_name=$4
  local policy_arn="arn:aws:iam::${account_id}:policy/${policy_name}"

  log_info "$account_id" "Verificando política: $policy_name"

  # Normalizar el documento para comparación (ordenado, sin espacios)
  local new_doc
  new_doc=$(echo "$policy_document" | python3 -c "
import sys, json
doc = json.load(sys.stdin)
print(json.dumps(doc, separators=(',',':'), sort_keys=True))
")

  # Verificar si la política ya existe
  if aws iam get-policy --policy-arn "$policy_arn" &>/dev/null; then
    log_info "$account_id" "  Política existe — verificando si hay cambios..."

    local default_version
    default_version=$(aws iam get-policy \
      --policy-arn "$policy_arn" \
      --query "Policy.DefaultVersionId" \
      --output text)

    local current_doc
    current_doc=$(aws iam get-policy-version \
      --policy-arn "$policy_arn" \
      --version-id "$default_version" \
      --query "PolicyVersion.Document" \
      --output json | python3 -c "
import sys, json
doc = json.load(sys.stdin)
print(json.dumps(doc, separators=(',',':'), sort_keys=True))
")

    if [ "$current_doc" == "$new_doc" ]; then
      log_ok "$account_id" "  Sin cambios: $policy_name"
    else
      log_info "$account_id" "  Cambios detectados — creando nueva versión..."

      # Limpiar versión más antigua si ya hay 5 (límite de AWS)
      local version_count
      version_count=$(aws iam list-policy-versions \
        --policy-arn "$policy_arn" \
        --query "length(Versions)" \
        --output text)

      if [ "$version_count" -ge 5 ]; then
        local oldest_version
        oldest_version=$(aws iam list-policy-versions \
          --policy-arn "$policy_arn" \
          --query "Versions[?!IsDefaultVersion] | sort_by(@, &CreateDate) | [0].VersionId" \
          --output text)
        log_info "$account_id" "  Eliminando versión antigua: $oldest_version"
        aws iam delete-policy-version \
          --policy-arn "$policy_arn" \
          --version-id "$oldest_version"
      fi

      aws iam create-policy-version \
        --policy-arn "$policy_arn" \
        --policy-document "$new_doc" \
        --set-as-default
      log_ok "$account_id" "  Política actualizada: $policy_name"
    fi
  else
    log_info "$account_id" "  Política no existe — creando..."
    aws iam create-policy \
      --policy-name "$policy_name" \
      --policy-document "$new_doc" \
      --tags Key=CC,Value=11709 Key=Team,Value=Arlington Key=Email,Value=l-cybertron@uolinc.com
    log_ok "$account_id" "  Política creada: $policy_name"
  fi

  # Attach al role si fue resuelto
  if [ -n "$role_name" ]; then
    local already_attached
    already_attached=$(aws iam list-attached-role-policies \
      --role-name "$role_name" \
      --query "AttachedPolicies[?PolicyArn=='${policy_arn}'].PolicyArn" \
      --output text 2>/dev/null || echo "")

    if [ -n "$already_attached" ]; then
      log_info "$account_id" "  Ya adjunta a role: $role_name"
    else
      log_info "$account_id" "  Adjuntando a role: $role_name"
      aws iam attach-role-policy \
        --role-name "$role_name" \
        --policy-arn "$policy_arn"
      log_ok "$account_id" "  Adjuntada: $policy_name → $role_name"
    fi
  else
    log_warn "$account_id" "  Role con prefijo '${LAMBDA_ROLE_PREFIX}' no encontrado — attach omitido"
  fi
}

# =============================================================================
# FUNCIÓN: crear las 4 políticas IAM directamente via AWS CLI
# =============================================================================
create_iam_policies() {
  local account_id=$1

  log_info "$account_id" "Creando/verificando las 4 políticas IAM..."

  # Resolver el role una sola vez para todas las políticas
  local lambda_role
  lambda_role=$(resolve_lambda_role)
  if [ -n "$lambda_role" ]; then
    log_ok "$account_id" "Role Lambda resuelto: $lambda_role"
  else
    log_warn "$account_id" "No se encontró role con prefijo '${LAMBDA_ROLE_PREFIX}' — las políticas se crearán sin attach"
  fi

  create_or_update_policy "$account_id" "CreateFeaturesStackLambdaExecutionManagedPolicy1" "$POLICY1_DOCUMENT" "$lambda_role" || return 1
  create_or_update_policy "$account_id" "CreateFeaturesStackLambdaExecutionManagedPolicy2" "$POLICY2_DOCUMENT" "$lambda_role" || return 1
  create_or_update_policy "$account_id" "CreateFeaturesStackLambdaExecutionManagedPolicy3" "$POLICY3_DOCUMENT" "$lambda_role" || return 1
  create_or_update_policy "$account_id" "CreateFeaturesStackLambdaExecutionManagedPolicy4" "$POLICY4_DOCUMENT" "$lambda_role" || return 1

  log_ok "$account_id" "Las 4 políticas fueron creadas/verificadas y adjuntadas correctamente"
}

# =============================================================================
# FUNCIÓN: resolver TODOS los stacks que empiecen con el prefijo
# Retorna una lista separada por newlines
# =============================================================================
resolve_all_stacks() {
  local account_id=$1

  aws cloudformation list-stacks \
    --region "$REGION" \
    --stack-status-filter \
      CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE \
      UPDATE_ROLLBACK_FAILED UPDATE_IN_PROGRESS UPDATE_ROLLBACK_IN_PROGRESS \
      ROLLBACK_COMPLETE ROLLBACK_FAILED \
    --query "StackSummaries[?starts_with(StackName, '${STACK_NAME_PREFIX}')].StackName" \
    --output text 2>/dev/null || echo ""
}

# =============================================================================
# FUNCIÓN: obtener el estado actual del stack
# =============================================================================
get_stack_status() {
  local account_id=$1
  local stack_name=$2

  aws cloudformation describe-stacks \
    --stack-name "$stack_name" \
    --region "$REGION" \
    --query "Stacks[0].StackStatus" \
    --output text 2>/dev/null || echo "NOT_FOUND"
}

# =============================================================================
# FUNCIÓN: triggerear el update del stack según su estado
# =============================================================================
trigger_stack_update() {
  local account_id=$1
  local stack_name=$2
  local status
  status=$(get_stack_status "$account_id" "$stack_name")

  log_info "$account_id" "Stack encontrado: $stack_name"
  log_info "$account_id" "Estado actual:    $status"

  case "$status" in
    "UPDATE_ROLLBACK_COMPLETE")
      log_info "$account_id" "Lanzando update del stack..."
      if [ -n "$TEMPLATE_URL" ]; then
        aws cloudformation update-stack \
          --stack-name "$stack_name" \
          --region "$REGION" \
          --template-url "$TEMPLATE_URL" \
          --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
      else
        aws cloudformation update-stack \
          --stack-name "$stack_name" \
          --region "$REGION" \
          --use-previous-template \
          --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
      fi
      log_ok "$account_id" "Update del stack iniciado"
      ;;

    "UPDATE_ROLLBACK_FAILED")
      log_info "$account_id" "Stack en UPDATE_ROLLBACK_FAILED — ejecutando continue-update-rollback..."
      aws cloudformation continue-update-rollback \
        --stack-name "$stack_name" \
        --region "$REGION"
      log_ok "$account_id" "continue-update-rollback iniciado"
      ;;

    "ROLLBACK_COMPLETE")
      log_warn "$account_id" "Stack en ROLLBACK_COMPLETE — necesita ser recreado, no solo actualizado."
      log_warn "$account_id" "Acción manual requerida para esta cuenta."
      ;;

    "UPDATE_IN_PROGRESS"|"UPDATE_ROLLBACK_IN_PROGRESS")
      log_warn "$account_id" "Stack ya tiene una operación en progreso ($status), saltando update..."
      ;;

    "NOT_FOUND")
      log_error "$account_id" "Stack no encontrado en la región $REGION"
      ;;

    *)
      log_warn "$account_id" "Estado inesperado '$status' — revisar manualmente"
      ;;
  esac
}

# =============================================================================
# FUNCIÓN: procesar una cuenta completa
# =============================================================================
process_account() {
  local account_id=$1
  echo ""
  echo "============================================================"
  echo " Procesando cuenta: $account_id"
  echo "============================================================"

  # Asumir role
  assume_role "$account_id" || return 1

  # Resolver todos los stacks con el prefijo
  local stacks_raw
  stacks_raw=$(resolve_all_stacks "$account_id")

  if [ -z "$stacks_raw" ]; then
    log_error "$account_id" "No se encontró ningún stack con prefijo '${STACK_NAME_PREFIX}' en $REGION"
    clear_credentials
    return 1
  fi

  # Convertir output (tab-separated) en array
  IFS=$'\t\n' read -r -a stack_list <<< "$stacks_raw"
  log_ok "$account_id" "Stacks encontrados: ${#stack_list[@]}"
  for s in "${stack_list[@]}"; do
    log_info "$account_id" "  → $s"
  done

  # Limpiar recursos huérfanos (solo una vez por cuenta, no por stack)
  cleanup_iam_role  "$account_id" || log_error "$account_id" "Falló la limpieza del IAM Role"
  cleanup_ecr_repo  "$account_id" || log_error "$account_id" "Falló la limpieza del ECR repo"

  # Crear las 4 políticas IAM antes del update (solo una vez por cuenta)
  create_iam_policies "$account_id" || {
    log_error "$account_id" "Falló la creación de políticas — abortando updates para esta cuenta"
    clear_credentials
    return 1
  }

  # Triggerear el update en cada stack encontrado
  local stack_errors=0
  for stack_name in "${stack_list[@]}"; do
    echo ""
    log_info "$account_id" "── Procesando stack: $stack_name"
    trigger_stack_update "$account_id" "$stack_name" || {
      log_error "$account_id" "Falló el update de: $stack_name"
      (( stack_errors++ )) || true
    }
  done

  # Limpiar credenciales
  clear_credentials

  if [ "$stack_errors" -gt 0 ]; then
    log_error "$account_id" "$stack_errors stack(s) fallaron en esta cuenta"
    return 1
  fi

  log_ok "$account_id" "Cuenta procesada ✓ (${#stack_list[@]} stacks actualizados)"
}

# =============================================================================
# MAIN
# =============================================================================
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║        CloudFormation Cleanup & Update Script            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Stack prefix: $STACK_NAME_PREFIX*"
echo "Región:  $REGION"
echo "Cuentas: ${#ACCOUNTS[@]}"
echo ""

# Verificar que hay cuentas configuradas
if [ ${#ACCOUNTS[@]} -eq 0 ]; then
  echo -e "${RED}ERROR: No hay cuentas configuradas en el array ACCOUNTS${NC}"
  exit 1
fi

# Verificar que la cuenta actual puede hacer AssumeRole
log_info "central" "Verificando identidad de la cuenta central..."
CENTRAL_ACCOUNT=$(aws sts get-caller-identity --query "Account" --output text)
log_ok "central" "Ejecutando desde cuenta: $CENTRAL_ACCOUNT"

# Resumen de lo que se va a hacer
echo ""
echo "Se ejecutará en las siguientes cuentas:"
for acc in "${ACCOUNTS[@]}"; do
  echo "  → $acc"
done
echo ""
read -p "¿Continuar? (y/N): " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Cancelado."; exit 0; }

# Procesar cada cuenta
FAILED_ACCOUNTS=()
for account_id in "${ACCOUNTS[@]}"; do
  process_account "$account_id" || FAILED_ACCOUNTS+=("$account_id")
done

# Resumen final
echo ""
echo "============================================================"
echo " RESUMEN FINAL"
echo "============================================================"
echo "Total cuentas:  ${#ACCOUNTS[@]}"
echo "Exitosas:       $(( ${#ACCOUNTS[@]} - ${#FAILED_ACCOUNTS[@]} ))"
echo "Con errores:    ${#FAILED_ACCOUNTS[@]}"

if [ ${#FAILED_ACCOUNTS[@]} -gt 0 ]; then
  echo ""
  echo -e "${RED}Cuentas con errores:${NC}"
  for acc in "${FAILED_ACCOUNTS[@]}"; do
    echo "  ✗ $acc"
  done
  exit 1
else
  echo ""
  echo -e "${GREEN}Todas las cuentas procesadas exitosamente ✓${NC}"
fi
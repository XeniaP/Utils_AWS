"""
delete_trendmicro_aws_resources.py
====================================
Elimina todos los recursos AWS desplegados por Trend Micro Vision One,
identificados por el tag TrendMicroProduct.

Soporta ejecución MULTI-CUENTA desde la cuenta master de AWS Organizations,
haciendo AssumeRole en cada cuenta miembro automáticamente.

Tags soportados (según documentación oficial):
  - cam      → Core features & Cyber Risk Exposure Management
  - ct       → Cloud Detections for AWS CloudTrail
  - cs       → Container Protection for AWS ECS
  - avtd     → Agentless Vulnerability & Threat Detection
  - fss      → File Security Storage
  - dspm     → Data Security Posture
  - rtpm     → Real-Time Posture Monitoring
  - vpcflow  → Cloud Detections for VPC Flow Logs
  - seclake  → Cloud Detections for Amazon Security Lake

INSTRUCCIONES:
  1. Ejecutar con DRY_RUN = True para revisar qué se eliminará
  2. Revisar el archivo resources_to_delete_FECHA.json generado
  3. Cambiar DRY_RUN = False y volver a ejecutar para eliminar

PREREQUISITOS EN AWS:
  - La cuenta master necesita: organizations:ListAccounts
  - Cada cuenta miembro debe tener un IAM Role con:
      * Nombre: ASSUME_ROLE_NAME (ver configuración abajo)
      * Trust policy que permita AssumeRole desde la cuenta master
      * Permisos: tag:GetResources + eliminación por servicio
  - Si usas AWS Control Tower o StackSets, el rol OrganizationAccountAccessRole
    ya existe en todas las cuentas y puede usarse directamente.

REQUISITOS:
  pip install boto3
"""

import boto3
import json
import time
import logging
import concurrent.futures
from datetime import datetime
from botocore.exceptions import ClientError

# --- CONFIGURACIÓN ------------------------------------------------------------

DRY_RUN = False  # [WARN] Cambiar a False solo cuando estés completamente seguro

TAG_KEY = "TrendMicroProduct"

# Filtrar por valores específicos, o dejar vacío [] para todos los features
TAG_VALUES = []  # Ej: ["cam", "ct"] o [] para todos

# Regiones a procesar. Dejar vacío [] para auto-detectar todas las regiones
REGIONS = []

# --- CONFIGURACIÓN MULTI-CUENTA -----------------------------------------------

# Nombre del rol a asumir en cada cuenta miembro.
# Opciones comunes:
#   "OrganizationAccountAccessRole"  → creado por AWS Organizations por defecto
#   "AWSControlTowerExecution"       → creado por AWS Control Tower
#   "TrendMicroCleanupRole"          → rol personalizado que hayas creado
ASSUME_ROLE_NAME = "OrganizationAccountAccessRole"

# Cuentas a procesar:
#   []          → auto-detectar TODAS las cuentas activas de la organización
#   ["123456789012", "234567890123"]  → solo estas cuentas específicas
TARGET_ACCOUNTS = []

# Excluir cuentas específicas (ej: cuentas de audit/log archive)
EXCLUDED_ACCOUNTS = []

# Procesar cuentas en paralelo (más rápido, pero logs entremezclados)
PARALLEL_ACCOUNTS = False
MAX_WORKERS = 5

# --- LOGGING ------------------------------------------------------------------

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"trendmicro_cleanup_{TIMESTAMP}.log"
REPORT_FILE = f"resources_to_delete_{TIMESTAMP}.json"

import sys
import io

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(stream=io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace"))
    ]
)
log = logging.getLogger(__name__)

# --- HELPERS ------------------------------------------------------------------

def parse_arn(arn):
    parts = arn.split(":")
    return {
        "partition": parts[1] if len(parts) > 1 else "",
        "service":   parts[2] if len(parts) > 2 else "",
        "region":    parts[3] if len(parts) > 3 else "",
        "account":   parts[4] if len(parts) > 4 else "",
        "resource":  ":".join(parts[5:]) if len(parts) > 5 else "",
    }

def resource_id(arn):
    resource = parse_arn(arn)["resource"]
    return resource.split("/")[-1] if "/" in resource else resource.split(":")[-1]

def safe_delete(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
        return True, None
    except ClientError as e:
        return False, e.response["Error"]["Code"] + ": " + e.response["Error"]["Message"]
    except Exception as e:
        return False, str(e)

def make_client(session, service, region=None):
    if region:
        return session.client(service, region_name=region)
    return session.client(service)

# --- ASSUME ROLE --------------------------------------------------------------

def get_session_for_account(account_id, role_name):
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = boto3.client("sts")
    try:
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"TrendMicroCleanup-{account_id}",
            DurationSeconds=3600
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    except ClientError as e:
        log.error(f"  [AssumeRole FAILED] cuenta {account_id} → {e.response['Error']['Message']}")
        return None

# --- OBTENER CUENTAS DE LA ORGANIZACIÓN ---------------------------------------

def get_organization_accounts():
    org = boto3.client("organizations")
    paginator = org.get_paginator("list_accounts")
    accounts = []
    try:
        for page in paginator.paginate():
            for acct in page["Accounts"]:
                if acct["Status"] == "ACTIVE":
                    accounts.append({"id": acct["Id"], "name": acct["Name"], "email": acct["Email"]})
    except ClientError as e:
        log.error(f"Error listando cuentas: {e}")
        log.error("Asegúrate de ejecutar desde la cuenta master con organizations:ListAccounts")
        raise
    return accounts

def get_master_account_id():
    return boto3.client("sts").get_caller_identity()["Account"]

# --- HANDLERS DE ELIMINACIÓN --------------------------------------------------

def delete_cloudformation(arn, region, session):
    cf = make_client(session, "cloudformation", region)
    return safe_delete(cf.delete_stack, StackName=resource_id(arn))

def delete_iam_role(arn, region, session):
    iam = make_client(session, "iam")
    role_name = resource_id(arn)
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for p in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        for prof in iam.list_instance_profiles_for_role(RoleName=role_name)["InstanceProfiles"]:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=prof["InstanceProfileName"], RoleName=role_name)
    except ClientError:
        pass
    return safe_delete(iam.delete_role, RoleName=role_name)

def delete_iam_policy(arn, region, session):
    iam = make_client(session, "iam")
    try:
        entities = iam.list_entities_for_policy(PolicyArn=arn)
        for role in entities.get("PolicyRoles", []):
            iam.detach_role_policy(RoleName=role["RoleName"], PolicyArn=arn)
        for user in entities.get("PolicyUsers", []):
            iam.detach_user_policy(UserName=user["UserName"], PolicyArn=arn)
        for grp in entities.get("PolicyGroups", []):
            iam.detach_group_policy(GroupName=grp["GroupName"], PolicyArn=arn)
        for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]:
            if not v["IsDefaultVersion"]:
                iam.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])
    except ClientError:
        pass
    return safe_delete(iam.delete_policy, PolicyArn=arn)

def delete_iam_oidc_provider(arn, region, session):
    iam = make_client(session, "iam")
    return safe_delete(iam.delete_open_id_connect_provider, OpenIDConnectProviderArn=arn)

def delete_iam_instance_profile(arn, region, session):
    iam = make_client(session, "iam")
    profile_name = resource_id(arn)
    try:
        roles = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Roles"]
        for role in roles:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role["RoleName"])
    except ClientError:
        pass
    return safe_delete(iam.delete_instance_profile, InstanceProfileName=profile_name)

def delete_lambda(arn, region, session):
    lam = make_client(session, "lambda", region)
    return safe_delete(lam.delete_function, FunctionName=resource_id(arn))

def delete_cloudwatch_log_group(arn, region, session):
    logs = make_client(session, "logs", region)
    log_group = arn.split(":log-group:")[-1].split(":")[0]
    return safe_delete(logs.delete_log_group, logGroupName=log_group)

def delete_sqs(arn, region, session):
    sqs = make_client(session, "sqs", region)
    queue_name = resource_id(arn)
    account = parse_arn(arn)["account"]
    queue_url = f"https://sqs.{region}.amazonaws.com/{account}/{queue_name}"
    return safe_delete(sqs.delete_queue, QueueUrl=queue_url)

def delete_sns_topic(arn, region, session):
    sns = make_client(session, "sns", region)
    return safe_delete(sns.delete_topic, TopicArn=arn)

def delete_eventbridge_rule(arn, region, session):
    eb = make_client(session, "events", region)
    rule_name = resource_id(arn)
    try:
        targets = eb.list_targets_by_rule(Rule=rule_name)["Targets"]
        if targets:
            eb.remove_targets(Rule=rule_name, Ids=[t["Id"] for t in targets])
    except ClientError:
        pass
    return safe_delete(eb.delete_rule, Name=rule_name, Force=True)

def delete_s3_bucket(arn, region, session):
    s3 = make_client(session, "s3", region)
    bucket = resource_id(arn)
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", [])]
            objects += [{"Key": o["Key"], "VersionId": o["VersionId"]}
                        for o in page.get("DeleteMarkers", [])]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    except ClientError:
        pass
    return safe_delete(s3.delete_bucket, Bucket=bucket)

def delete_ssm_parameter(arn, region, session):
    ssm = make_client(session, "ssm", region)
    param_name = "/" + arn.split(":parameter/")[-1]
    return safe_delete(ssm.delete_parameter, Name=param_name)

def delete_secrets_manager(arn, region, session):
    sm = make_client(session, "secretsmanager", region)
    return safe_delete(sm.delete_secret, SecretId=arn, ForceDeleteWithoutRecovery=True)

def delete_kms_key(arn, region, session):
    kms = make_client(session, "kms", region)
    ok, err = safe_delete(kms.schedule_key_deletion, KeyId=resource_id(arn), PendingWindowInDays=7)
    if ok:
        return True, "Programada eliminación en 7 días (mínimo KMS)"
    return ok, err

def delete_step_function(arn, region, session):
    sf = make_client(session, "stepfunctions", region)
    return safe_delete(sf.delete_state_machine, stateMachineArn=arn)

def delete_appconfig(arn, region, session):
    ac = make_client(session, "appconfig", region)
    return safe_delete(ac.delete_application, ApplicationId=resource_id(arn))

def delete_ecs_task_definition(arn, region, session):
    ecs = make_client(session, "ecs", region)
    ok, err = safe_delete(ecs.deregister_task_definition, taskDefinition=arn)
    if ok:
        safe_delete(ecs.delete_task_definitions, taskDefinitions=[arn])
    return ok, err

def delete_ec2_vpc(arn, region, session):
    ec2 = make_client(session, "ec2", region)
    return safe_delete(ec2.delete_vpc, VpcId=resource_id(arn))

def delete_ec2_subnet(arn, region, session):
    ec2 = make_client(session, "ec2", region)
    return safe_delete(ec2.delete_subnet, SubnetId=resource_id(arn))

def delete_ec2_security_group(arn, region, session):
    ec2 = make_client(session, "ec2", region)
    return safe_delete(ec2.delete_security_group, GroupId=resource_id(arn))

def delete_ec2_volume(arn, region, session):
    ec2 = make_client(session, "ec2", region)
    return safe_delete(ec2.delete_volume, VolumeId=resource_id(arn))

def delete_ec2_internet_gateway(arn, region, session):
    ec2 = make_client(session, "ec2", region)
    igw_id = resource_id(arn)
    try:
        igw = ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])
        for att in igw["InternetGateways"][0].get("Attachments", []):
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=att["VpcId"])
    except ClientError:
        pass
    return safe_delete(ec2.delete_internet_gateway, InternetGatewayId=igw_id)

def delete_ec2_nat_gateway(arn, region, session):
    ec2 = make_client(session, "ec2", region)
    return safe_delete(ec2.delete_nat_gateway, NatGatewayId=resource_id(arn))

def delete_ec2_route_table(arn, region, session):
    ec2 = make_client(session, "ec2", region)
    return safe_delete(ec2.delete_route_table, RouteTableId=resource_id(arn))

def delete_ec2_eip(arn, region, session):
    ec2 = make_client(session, "ec2", region)
    return safe_delete(ec2.release_address, AllocationId=resource_id(arn))

def delete_cloudtrail(arn, region, session):
    ct = make_client(session, "cloudtrail", region)
    return safe_delete(ct.delete_trail, Name=arn)

# --- MAPA DE SERVICIOS A HANDLERS ---------------------------------------------

SERVICE_HANDLERS = {
    ("cloudformation", "stack"):        delete_cloudformation,
    ("cloudformation", "stackset"):     lambda a, r, s: (False, "StackSet requiere eliminación manual"),
    ("iam", "role"):                    delete_iam_role,
    ("iam", "policy"):                  delete_iam_policy,
    ("iam", "oidc-provider"):           delete_iam_oidc_provider,
    ("iam", "instance-profile"):        delete_iam_instance_profile,
    ("lambda", "function"):             delete_lambda,
    ("logs", "log-group"):              delete_cloudwatch_log_group,
    ("sqs", ""):                        delete_sqs,
    ("sns", ""):                        delete_sns_topic,
    ("events", "rule"):                 delete_eventbridge_rule,
    ("s3", ""):                         delete_s3_bucket,
    ("ssm", "parameter"):               delete_ssm_parameter,
    ("secretsmanager", "secret"):       delete_secrets_manager,
    ("kms", "key"):                     delete_kms_key,
    ("states", "stateMachine"):         delete_step_function,
    ("appconfig", "application"):       delete_appconfig,
    ("ecs", "task-definition"):         delete_ecs_task_definition,
    ("ec2", "vpc"):                     delete_ec2_vpc,
    ("ec2", "subnet"):                  delete_ec2_subnet,
    ("ec2", "security-group"):          delete_ec2_security_group,
    ("ec2", "volume"):                  delete_ec2_volume,
    ("ec2", "internet-gateway"):        delete_ec2_internet_gateway,
    ("ec2", "natgateway"):              delete_ec2_nat_gateway,
    ("ec2", "route-table"):             delete_ec2_route_table,
    ("ec2", "elastic-ip"):              delete_ec2_eip,
    ("cloudtrail", "trail"):            delete_cloudtrail,
}

def get_handler(arn):
    parsed = parse_arn(arn)
    service = parsed["service"]
    resource = parsed["resource"]
    if "/" in resource:
        rtype = resource.split("/")[0]
    elif ":" in resource:
        rtype = resource.split(":")[0]
    else:
        rtype = resource
    return SERVICE_HANDLERS.get((service, rtype)) or SERVICE_HANDLERS.get((service, ""))

# --- OBTENER RECURSOS POR TAG --------------------------------------------------

def get_tagged_resources(region, tag_key, tag_values, session):
    client = session.client("resourcegroupstaggingapi", region_name=region)
    paginator = client.get_paginator("get_resources")
    tag_filter = {"Key": tag_key}
    if tag_values:
        tag_filter["Values"] = tag_values
    resources = []
    try:
        for page in paginator.paginate(TagFilters=[tag_filter]):
            resources.extend(page["ResourceTagMappingList"])
    except ClientError as e:
        log.warning(f"    [{region}] Error: {e}")
    return resources

# --- CONSTANTES GLOBALES ------------------------------------------------------

PRIORITY_ORDER = [
    "ecs", "lambda", "states", "events", "sqs", "sns",
    "s3", "secretsmanager", "ssm", "appconfig", "logs",
    "cloudtrail", "ec2", "kms", "iam", "cloudformation"
]

FEATURE_NAMES = {
    "cam":      "Core / Cyber Risk Exposure Management",
    "ct":       "Cloud Detections for CloudTrail",
    "cs":       "Container Protection for ECS",
    "avtd":     "Agentless Vulnerability & Threat Detection",
    "fss":      "File Security Storage",
    "dspm":     "Data Security Posture",
    "rtpm":     "Real-Time Posture Monitoring",
    "vpcflow":  "Cloud Detections for VPC Flow Logs",
    "seclake":  "Cloud Detections for Security Lake",
}

# --- PROCESAR UNA CUENTA ------------------------------------------------------

def process_account(account, regions):
    account_id = account["id"]
    account_name = account.get("name", account_id)
    prefix = f"[{account_id} | {account_name}]"

    log.info(f"\n{'-'*60}")
    log.info(f"[ACCOUNT] {prefix}")
    log.info(f"{'-'*60}")

    session = get_session_for_account(account_id, ASSUME_ROLE_NAME)
    if session is None:
        return {
            "account_id": account_id, "account_name": account_name,
            "status": "ASSUME_ROLE_FAILED", "resources": [],
            "deleted": [], "errors": [], "no_handler": [], "manual": []
        }

    return _process_with_session(account_id, account_name, session, regions, prefix)


def _process_with_session(account_id, account_name, session, regions, prefix):
    all_resources = []
    for region in regions:
        resources = get_tagged_resources(region, TAG_KEY, TAG_VALUES, session)
        if resources:
            log.info(f"  [OK] {prefix} {region}: {len(resources)} recursos")
            for r in resources:
                r["_region"] = region
                r["_account_id"] = account_id
                r["_account_name"] = account_name
            all_resources.extend(resources)

    if not all_resources:
        log.info(f"  [SKIP] {prefix} Sin recursos con el tag.")
        return {
            "account_id": account_id, "account_name": account_name,
            "status": "NO_RESOURCES", "resources": [],
            "deleted": [], "errors": [], "no_handler": [], "manual": []
        }

    log.info(f"  [INFO] {prefix} Total: {len(all_resources)} recursos")
    tag_counts = {}
    for r in all_resources:
        tags = {t["Key"]: t["Value"] for t in r.get("Tags", [])}
        val = tags.get(TAG_KEY, "unknown")
        tag_counts[val] = tag_counts.get(val, 0) + 1
    for val, count in sorted(tag_counts.items()):
        log.info(f"    {val:10s} ({FEATURE_NAMES.get(val, val)}): {count}")

    result = {
        "account_id": account_id, "account_name": account_name,
        "status": "DRY_RUN" if DRY_RUN else "PROCESSED",
        "resources": all_resources,
        "deleted": [], "errors": [], "no_handler": [], "manual": []
    }

    if DRY_RUN:
        return result

    all_resources.sort(key=lambda r: PRIORITY_ORDER.index(
        parse_arn(r["ResourceARN"])["service"])
        if parse_arn(r["ResourceARN"])["service"] in PRIORITY_ORDER else 99)

    for r in all_resources:
        arn = r["ResourceARN"]
        region = r["_region"]
        tags = {t["Key"]: t["Value"] for t in r.get("Tags", [])}
        tag_val = tags.get(TAG_KEY, "?")
        handler = get_handler(arn)

        if handler is None:
            log.warning(f"  [NO HANDLER] {prefix} {arn}")
            result["no_handler"].append(arn)
            continue

        ok, err = handler(arn, region, session)

        if ok:
            log.info(f"  [[OK] DELETED] {prefix} [{tag_val}] {arn} → {err or 'OK'}")
            result["deleted"].append(arn)
        else:
            if err and ("MANUAL" in err or "StackSet" in err):
                log.warning(f"  [[WARN]  MANUAL] {prefix} [{tag_val}] {arn} → {err}")
                result["manual"].append({"arn": arn, "reason": err})
            else:
                log.error(f"  [[FAIL] ERROR]   {prefix} [{tag_val}] {arn} → {err}")
                result["errors"].append({"arn": arn, "error": err})

        time.sleep(0.05)

    return result

# --- MAIN ---------------------------------------------------------------------

def main():
    master_id = get_master_account_id()
    log.info(f"\n{'='*60}")
    log.info(f"[START] Trend Micro Vision One — AWS Multi-Account Cleanup")
    log.info(f"   Cuenta master:  {master_id}")
    log.info(f"   Rol asumido:    {ASSUME_ROLE_NAME}")
    log.info(f"   DRY RUN:        {'[OK] Sí (solo listar)' if DRY_RUN else '[FAIL] No (ELIMINACIÓN REAL)'}")
    log.info(f"   Paralelo:       {'Sí (' + str(MAX_WORKERS) + ' workers)' if PARALLEL_ACCOUNTS else 'No (secuencial)'}")
    log.info(f"{'='*60}\n")

    # Obtener cuentas
    if TARGET_ACCOUNTS:
        accounts = [{"id": a, "name": a} for a in TARGET_ACCOUNTS]
        log.info(f"[LIST] Usando lista manual: {len(accounts)} cuentas")
    else:
        log.info("[SEARCH] Obteniendo cuentas de AWS Organizations...")
        accounts = get_organization_accounts()
        log.info(f"   {len(accounts)} cuentas activas encontradas")

    if EXCLUDED_ACCOUNTS:
        accounts = [a for a in accounts if a["id"] not in EXCLUDED_ACCOUNTS]
        log.info(f"   {len(accounts)} cuentas tras exclusiones")

    master_account = next((a for a in accounts if a["id"] == master_id), {"id": master_id, "name": "master"})
    member_accounts = [a for a in accounts if a["id"] != master_id]

    log.info(f"\nCuentas a procesar: {len(accounts)} total")
    for a in accounts:
        marker = "[MASTER] master " if a["id"] == master_id else "   miembro"
        log.info(f"  {marker} | {a['id']} | {a.get('name', '')}")

    # Obtener regiones
    regions = REGIONS
    if not regions:
        log.info("\n[REGIONS] Auto-detectando regiones...")
        ec2 = boto3.client("ec2", region_name="us-east-1")
        regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
        log.info(f"   {len(regions)} regiones")

    all_results = []

    # Cuenta master — usar sesión actual sin AssumeRole
    log.info(f"\n[MASTER] Procesando cuenta MASTER ({master_id}) con credenciales actuales...")
    master_session = boto3.Session()
    master_result = _process_with_session(
        master_id, master_account.get("name", master_id),
        master_session, regions, f"[{master_id} | master]"
    )
    all_results.append(master_result)

    # Cuentas miembro
    if PARALLEL_ACCOUNTS and len(member_accounts) > 1:
        log.info(f"\n[PARALLEL] Procesando {len(member_accounts)} cuentas EN PARALELO (workers={MAX_WORKERS})...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_account, acct, regions): acct for acct in member_accounts}
            for future in concurrent.futures.as_completed(futures):
                all_results.append(future.result())
    else:
        log.info(f"\n[LOOP] Procesando {len(member_accounts)} cuentas miembro en secuencia...")
        for acct in member_accounts:
            all_results.append(process_account(acct, regions))

    # Guardar reporte
    with open(REPORT_FILE, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    log.info(f"\n[SAVE] Reporte guardado en: {REPORT_FILE}")

    # Resumen global
    total_resources  = sum(len(r["resources"]) for r in all_results)
    total_deleted    = sum(len(r["deleted"])   for r in all_results)
    total_errors     = sum(len(r["errors"])    for r in all_results)
    total_manual     = sum(len(r["manual"])    for r in all_results)
    total_no_handler = sum(len(r["no_handler"])for r in all_results)
    failed_roles     = [r for r in all_results if r["status"] == "ASSUME_ROLE_FAILED"]

    log.info(f"\n{'='*60}")
    log.info("[SUMMARY] RESUMEN GLOBAL")
    log.info(f"{'='*60}")
    log.info(f"  Cuentas procesadas:          {len(all_results)}")
    log.info(f"  Cuentas sin acceso (rol):    {len(failed_roles)}")
    log.info(f"  Total recursos encontrados:  {total_resources}")

    if DRY_RUN:
        log.info(f"\n  [DRY-RUN] DRY-RUN — no se eliminó nada.")
        log.info(f"     Revisa '{REPORT_FILE}' y cambia DRY_RUN = False para ejecutar.")
    else:
        log.info(f"  [OK] Eliminados correctamente:  {total_deleted}")
        log.info(f"  [FAIL] Errores:                   {total_errors}")
        log.info(f"  [WARN]  Acción manual requerida:   {total_manual}")
        log.info(f"  [SKIP] Sin handler:                {total_no_handler}")

    if failed_roles:
        log.info(f"\n  Cuentas donde falló AssumeRole:")
        for r in failed_roles:
            log.info(f"    - {r['account_id']} ({r['account_name']})")
        log.info(f"\n  -->  Verifica que el rol '{ASSUME_ROLE_NAME}' existe en esas cuentas")
        log.info(f"     con trust policy hacia la cuenta master ({master_id}).")

    log.info(f"\n  [LOG] Log: {LOG_FILE}\n")

if __name__ == "__main__":
    main()
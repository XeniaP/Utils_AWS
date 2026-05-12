#!/bin/bash
# =============================================================================
# checklist.sh
# Compara los recursos desplegados en una cuenta de referencia contra
# las cuentas destino y genera un reporte de qué falta en cada una.
#
# Criterios de búsqueda:
#   - Cualquier recurso con tag TrendMicroProduct
#   - IAM Roles/Policies con "VisionOne" o "trendmicro" en el nombre
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURACIÓN — editar antes de ejecutar
# =============================================================================

ROLE_NAME="OrganizationAccountAccessRole"   # Role para AssumeRole en cada cuenta
REGION="us-east-1"
REFERENCE_ACCOUNT="390844781046"            # Cuenta de referencia (ya tiene todo desplegado)
REPORT_FILE="checklist_report_$(date +%Y%m%d_%H%M%S).txt"

# Cuentas destino a validar (NO incluir la de referencia)
TARGET_ACCOUNTS=(
  "136191772539"
  "586794439760"
  # ... agregar el resto
)

# =============================================================================
# COLORES
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  [$1] $2"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    [$1] $2"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  [$1] $2"; }
log_error() { echo -e "${RED}[ERROR]${NC} [$1] $2"; }
log_miss()  { echo -e "${RED}[MISS]${NC}  [$1] $2"; }

# Función para escribir al reporte y a stdout
report() { echo "$1" | tee -a "$REPORT_FILE"; }

# =============================================================================
# FUNCIÓN: asumir role
# =============================================================================
assume_role() {
  local account_id=$1
  local role_arn="arn:aws:iam::${account_id}:role/${ROLE_NAME}"

  local creds
  creds=$(aws sts assume-role \
    --role-arn "$role_arn" \
    --role-session-name "checklist-session-${account_id}" \
    --query "Credentials" \
    --output json 2>&1) || {
      log_error "$account_id" "No se pudo asumir el role: $creds"
      return 1
    }

  export AWS_ACCESS_KEY_ID=$(echo "$creds"     | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKeyId'])")
  export AWS_SECRET_ACCESS_KEY=$(echo "$creds" | python3 -c "import sys,json; print(json.load(sys.stdin)['SecretAccessKey'])")
  export AWS_SESSION_TOKEN=$(echo "$creds"     | python3 -c "import sys,json; print(json.load(sys.stdin)['SessionToken'])")
}

clear_credentials() {
  unset AWS_ACCESS_KEY_ID
  unset AWS_SECRET_ACCESS_KEY
  unset AWS_SESSION_TOKEN
}

# =============================================================================
# FUNCIONES DE RECOLECCIÓN DE RECURSOS
# Cada función retorna una lista de nombres separados por newline
# =============================================================================

# --- IAM Roles ---
get_iam_roles() {
  aws iam list-roles \
    --query "Roles[?contains(RoleName, 'VisionOne') || contains(RoleName, 'visionone') || contains(RoleName, 'trendmicro') || contains(RoleName, 'TrendMicro') || contains(RoleName, 'Vision-One') || contains(RoleName, 'tmv1') || contains(RoleName, 'container-security')].RoleName" \
    --output text 2>/dev/null | tr '\t' '\n' | sort
}

# --- IAM Policies (customer managed) ---
get_iam_policies() {
  aws iam list-policies \
    --scope Local \
    --query "Policies[?contains(PolicyName, 'VisionOne') || contains(PolicyName, 'visionone') || contains(PolicyName, 'trendmicro') || contains(PolicyName, 'TrendMicro') || contains(PolicyName, 'Vision-One') || contains(PolicyName, 'tmv1') || contains(PolicyName, 'CreateFeatures')].PolicyName" \
    --output text 2>/dev/null | tr '\t' '\n' | sort
}

# --- ECR Repositories (por tag TrendMicroProduct) ---
get_ecr_repos() {
  # Primero listar todos los repos
  local repos
  repos=$(aws ecr describe-repositories \
    --region "$REGION" \
    --query "repositories[].repositoryName" \
    --output text 2>/dev/null | tr '\t' '\n')

  # Filtrar los que tienen el tag TrendMicroProduct o nombre con trendmicro/visionone
  local result=()
  for repo in $repos; do
    local repo_arn
    repo_arn=$(aws ecr describe-repositories \
      --repository-names "$repo" \
      --region "$REGION" \
      --query "repositories[0].repositoryArn" \
      --output text 2>/dev/null)

    local has_tag
    has_tag=$(aws ecr list-tags-for-resource \
      --resource-arn "$repo_arn" \
      --region "$REGION" \
      --query "tags[?Key=='TrendMicroProduct'].Value" \
      --output text 2>/dev/null || echo "")

    if [ -n "$has_tag" ] || echo "$repo" | grep -qiE "trendmicro|visionone|vision-one|tmv1"; then
      result+=("$repo")
    fi
  done
  printf '%s\n' "${result[@]}" | sort
}

# --- S3 Buckets (por tag TrendMicroProduct) ---
get_s3_buckets() {
  local buckets
  buckets=$(aws s3api list-buckets \
    --query "Buckets[].Name" \
    --output text 2>/dev/null | tr '\t' '\n')

  local result=()
  for bucket in $buckets; do
    local has_tag
    has_tag=$(aws s3api get-bucket-tagging \
      --bucket "$bucket" \
      --query "TagSet[?Key=='TrendMicroProduct'].Value" \
      --output text 2>/dev/null || echo "")

    if [ -n "$has_tag" ] || echo "$bucket" | grep -qiE "trendmicro|visionone|vision-one|tmv1"; then
      result+=("$bucket")
    fi
  done
  printf '%s\n' "${result[@]}" | sort
}

# --- Lambda Functions (por tag TrendMicroProduct o nombre) ---
get_lambda_functions() {
  local functions
  functions=$(aws lambda list-functions \
    --region "$REGION" \
    --query "Functions[].FunctionName" \
    --output text 2>/dev/null | tr '\t' '\n')

  local result=()
  for fn in $functions; do
    local tags
    tags=$(aws lambda list-tags \
      --resource "arn:aws:lambda:${REGION}:$(aws sts get-caller-identity --query Account --output text):function:${fn}" \
      --region "$REGION" \
      --query "Tags.TrendMicroProduct" \
      --output text 2>/dev/null || echo "")

    if [ -n "$tags" ] && [ "$tags" != "None" ]; then
      result+=("$fn")
    elif echo "$fn" | grep -qiE "trendmicro|visionone|vision-one|tmv1|container-security"; then
      result+=("$fn")
    fi
  done
  printf '%s\n' "${result[@]}" | sort
}

# --- CloudFormation Stacks (por tag TrendMicroProduct o nombre) ---
get_cfn_stacks() {
  aws cloudformation list-stacks \
    --region "$REGION" \
    --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE ROLLBACK_COMPLETE \
    --query "StackSummaries[?contains(StackName, 'VisionOne') || contains(StackName, 'visionone') || contains(StackName, 'TrendMicro') || contains(StackName, 'trendmicro') || contains(StackName, 'Vision-One') || contains(StackName, 'tmv1')].StackName" \
    --output text 2>/dev/null | tr '\t' '\n' | sort
}

# --- CloudWatch Log Groups (por tag TrendMicroProduct o nombre) ---
get_log_groups() {
  aws logs describe-log-groups \
    --region "$REGION" \
    --query "logGroups[?contains(logGroupName, 'VisionOne') || contains(logGroupName, 'visionone') || contains(logGroupName, 'trendmicro') || contains(logGroupName, 'TrendMicro') || contains(logGroupName, 'Vision-One') || contains(logGroupName, 'tmv1') || contains(logGroupName, 'container-security')].logGroupName" \
    --output text 2>/dev/null | tr '\t' '\n' | sort
}

# --- EventBridge Rules (por tag TrendMicroProduct o nombre) ---
get_eventbridge_rules() {
  local rules
  rules=$(aws events list-rules \
    --region "$REGION" \
    --query "Rules[].Name" \
    --output text 2>/dev/null | tr '\t' '\n')

  local result=()
  for rule in $rules; do
    local tags
    tags=$(aws events list-tags-for-resource \
      --resource-arn "arn:aws:events:${REGION}:$(aws sts get-caller-identity --query Account --output text):rule/${rule}" \
      --region "$REGION" \
      --query "Tags[?Key=='TrendMicroProduct'].Value" \
      --output text 2>/dev/null || echo "")

    if [ -n "$tags" ] && [ "$tags" != "None" ]; then
      result+=("$rule")
    elif echo "$rule" | grep -qiE "trendmicro|visionone|vision-one|tmv1|container-security"; then
      result+=("$rule")
    fi
  done
  printf '%s\n' "${result[@]}" | sort
}

# --- Secrets Manager (por tag TrendMicroProduct o nombre) ---
get_secrets() {
  local secrets
  secrets=$(aws secretsmanager list-secrets \
    --region "$REGION" \
    --query "SecretList[].Name" \
    --output text 2>/dev/null | tr '\t' '\n')

  local result=()
  for secret in $secrets; do
    local tags
    tags=$(aws secretsmanager describe-secret \
      --secret-id "$secret" \
      --region "$REGION" \
      --query "Tags[?Key=='TrendMicroProduct'].Value" \
      --output text 2>/dev/null || echo "")

    if [ -n "$tags" ] && [ "$tags" != "None" ]; then
      result+=("$secret")
    elif echo "$secret" | grep -qiE "trendmicro|visionone|vision-one|tmv1|/V1CS/"; then
      result+=("$secret")
    fi
  done
  printf '%s\n' "${result[@]}" | sort
}

# Directorio temporal — se elimina automáticamente al salir
TMP_DIR=$(mktemp -d /tmp/checklist.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

# =============================================================================
# FUNCIÓN: normalizar un nombre eliminando sufijo aleatorio al final
# Detecta el último segmento separado por "-" si es alfanumérico de 8-13 chars
# Ejemplos:
#   MyRole-ABC123DEF          → MyRole
#   StackSet-VisionOne-XYZ99  → StackSet-VisionOne
#   CreateFeaturesStackPolicy → CreateFeaturesStackPolicy  (sin cambio)
# =============================================================================
strip_random_suffix() {
  python3 -c "
import sys, re
for line in sys.stdin:
    name = line.rstrip()
    if not name:
        continue
    # Sufijo aleatorio: ultimo segmento de 8-13 chars, solo alphanum (sin vocales pattern o hex-like)
    m = re.match(r'^(.+)-([A-Z0-9]{8,13})$', name)
    if m:
        print(m.group(1))
    else:
        print(name)
"
}

# =============================================================================
# FUNCIÓN: recolectar todos los recursos de una cuenta
# Guarda cada lista en un archivo bajo $TMP_DIR/<prefix>/<tipo>
# Si prefix=REF, normaliza los nombres eliminando sufijos aleatorios
# =============================================================================
collect_all_resources() {
  local account_id=$1
  local prefix=$2   # "REF" o "TGT"
  local dir="$TMP_DIR/$prefix"
  mkdir -p "$dir"

  # Para la cuenta de referencia normalizamos; para destino dejamos raw
  # y normalizamos también para que la comparación sea justa
  normalize() {
    if [ "$prefix" = "REF" ]; then
      strip_random_suffix
    else
      strip_random_suffix
    fi
  }

  log_info "$account_id" "Recolectando IAM Roles..."
  get_iam_roles         2>/dev/null | normalize | sort -u > "$dir/iam_roles.txt"    || true

  log_info "$account_id" "Recolectando IAM Policies..."
  get_iam_policies      2>/dev/null | normalize | sort -u > "$dir/iam_policies.txt" || true

  log_info "$account_id" "Recolectando ECR Repositories..."
  get_ecr_repos         2>/dev/null | normalize | sort -u > "$dir/ecr_repos.txt"    || true

  log_info "$account_id" "Recolectando S3 Buckets..."
  get_s3_buckets        2>/dev/null | normalize | sort -u > "$dir/s3_buckets.txt"   || true

  log_info "$account_id" "Recolectando Lambda Functions..."
  get_lambda_functions  2>/dev/null | normalize | sort -u > "$dir/lambdas.txt"      || true

  log_info "$account_id" "Recolectando CloudFormation Stacks..."
  get_cfn_stacks        2>/dev/null | normalize | sort -u > "$dir/cfn_stacks.txt"   || true

  log_info "$account_id" "Recolectando CloudWatch Log Groups..."
  get_log_groups        2>/dev/null | normalize | sort -u > "$dir/log_groups.txt"   || true

  log_info "$account_id" "Recolectando EventBridge Rules..."
  get_eventbridge_rules 2>/dev/null | normalize | sort -u > "$dir/events.txt"       || true

  log_info "$account_id" "Recolectando Secrets..."
  get_secrets           2>/dev/null | normalize | sort -u > "$dir/secrets.txt"      || true
}

# =============================================================================
# FUNCIÓN: comparar dos archivos de lista y reportar diferencias
# Compara por prefijo: un item de REF se considera presente en TGT si existe
# alguna línea en TGT que empiece con ese prefijo
# =============================================================================
compare_and_report() {
  local resource_type=$1
  local ref_file=$2
  local tgt_file=$3
  local account_id=$4

  [ -f "$ref_file" ] || touch "$ref_file"
  [ -f "$tgt_file" ] || touch "$tgt_file"

  local missing=()
  local ref_count tgt_count missing_count
  ref_count=$(grep -c . "$ref_file" 2>/dev/null || echo 0)
  tgt_count=$(grep -c . "$tgt_file" 2>/dev/null || echo 0)
  missing_count=0

  while IFS= read -r ref_item; do
    [ -z "$ref_item" ] && continue
    # Buscar en tgt alguna línea que empiece con el nombre normalizado de ref
    if ! grep -qF "$ref_item" "$tgt_file" 2>/dev/null; then
      missing+=("$ref_item")
      (( missing_count++ )) || true
    fi
  done < <(grep . "$ref_file" 2>/dev/null || true)

  report ""
  report "  ── $resource_type"
  report "     Referencia: $ref_count | Cuenta: $tgt_count | Faltantes: $missing_count"

  if [ ${#missing[@]} -eq 0 ]; then
    report "     ✅ Completo"
  else
    for m in "${missing[@]}"; do
      report "     ❌ FALTA: $m"
    done
  fi

  echo "$missing_count"
}

# =============================================================================
# MAIN
# =============================================================================
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         CloudFormation Deployment Checklist              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Cuenta de referencia: $REFERENCE_ACCOUNT"
echo "Región:               $REGION"
echo "Cuentas a validar:    ${#TARGET_ACCOUNTS[@]}"
echo "Reporte:              $REPORT_FILE"
echo ""

# Inicializar reporte
{
  echo "============================================================"
  echo " CHECKLIST DE DESPLIEGUE — $(date)"
  echo " Referencia: $REFERENCE_ACCOUNT | Región: $REGION"
  echo "============================================================"
} > "$REPORT_FILE"

# --- PASO 1: Recolectar recursos de la cuenta de referencia ---
echo -e "${CYAN}[PASO 1]${NC} Recolectando recursos de la cuenta de referencia: $REFERENCE_ACCOUNT"
assume_role "$REFERENCE_ACCOUNT"
collect_all_resources "$REFERENCE_ACCOUNT" "REF"
clear_credentials
log_ok "$REFERENCE_ACCOUNT" "Recolección completa ✓"
echo ""

# --- PASO 2: Comparar contra cada cuenta destino ---
echo -e "${CYAN}[PASO 2]${NC} Comparando contra cuentas destino..."

ACCOUNTS_OK=()
ACCOUNTS_INCOMPLETE=()

for account_id in "${TARGET_ACCOUNTS[@]}"; do
  echo ""
  echo "============================================================"
  echo -e " Validando cuenta: ${BOLD}$account_id${NC}"
  echo "============================================================"

  report ""
  report "============================================================"
  report " CUENTA: $account_id"
  report "============================================================"

  # Asumir role en la cuenta destino
  assume_role "$account_id" || {
    log_error "$account_id" "No se pudo asumir el role — saltando cuenta"
    report "  ERROR: No se pudo asumir el role"
    ACCOUNTS_INCOMPLETE+=("$account_id (sin acceso)")
    continue
  }

  # Recolectar recursos de la cuenta destino
  log_info "$account_id" "Recolectando recursos..."
  collect_all_resources "$account_id" "TGT"
  clear_credentials

  # Comparar cada tipo de recurso
  total_missing=0

  REF="$TMP_DIR/REF"
  TGT="$TMP_DIR/TGT"

  n=$(compare_and_report "IAM Roles"            "$REF/iam_roles.txt"   "$TGT/iam_roles.txt"   "$account_id"); (( total_missing += n )) || true
  n=$(compare_and_report "IAM Policies"         "$REF/iam_policies.txt" "$TGT/iam_policies.txt" "$account_id"); (( total_missing += n )) || true
  n=$(compare_and_report "ECR Repositories"     "$REF/ecr_repos.txt"   "$TGT/ecr_repos.txt"   "$account_id"); (( total_missing += n )) || true
  n=$(compare_and_report "S3 Buckets"           "$REF/s3_buckets.txt"  "$TGT/s3_buckets.txt"  "$account_id"); (( total_missing += n )) || true
  n=$(compare_and_report "Lambda Functions"     "$REF/lambdas.txt"     "$TGT/lambdas.txt"     "$account_id"); (( total_missing += n )) || true
  n=$(compare_and_report "CloudFormation Stacks" "$REF/cfn_stacks.txt" "$TGT/cfn_stacks.txt"  "$account_id"); (( total_missing += n )) || true
  n=$(compare_and_report "CloudWatch Log Groups" "$REF/log_groups.txt" "$TGT/log_groups.txt"  "$account_id"); (( total_missing += n )) || true
  n=$(compare_and_report "EventBridge Rules"    "$REF/events.txt"      "$TGT/events.txt"      "$account_id"); (( total_missing += n )) || true
  n=$(compare_and_report "Secrets Manager"      "$REF/secrets.txt"     "$TGT/secrets.txt"     "$account_id"); (( total_missing += n )) || true

  report ""
  if [ "$total_missing" -eq 0 ]; then
    report "  RESULTADO: ✅ COMPLETO — ningún recurso faltante"
    log_ok "$account_id" "✅ COMPLETO — ningún recurso faltante"
    ACCOUNTS_OK+=("$account_id")
  else
    report "  RESULTADO: ❌ INCOMPLETO — $total_missing recurso(s) faltante(s)"
    log_warn "$account_id" "❌ INCOMPLETO — $total_missing recurso(s) faltante(s)"
    ACCOUNTS_INCOMPLETE+=("$account_id ($total_missing faltantes)")
  fi
done

# =============================================================================
# RESUMEN FINAL
# =============================================================================
echo ""
echo "============================================================"
echo -e " ${BOLD}RESUMEN FINAL${NC}"
echo "============================================================"

report ""
report "============================================================"
report " RESUMEN FINAL"
report "============================================================"
report "Total cuentas validadas: ${#TARGET_ACCOUNTS[@]}"
report "Completas:    ${#ACCOUNTS_OK[@]}"
report "Incompletas:  ${#ACCOUNTS_INCOMPLETE[@]}"

echo "Total cuentas validadas: ${#TARGET_ACCOUNTS[@]}"
echo -e "${GREEN}Completas:${NC}    ${#ACCOUNTS_OK[@]}"
echo -e "${RED}Incompletas:${NC}  ${#ACCOUNTS_INCOMPLETE[@]}"

if [ ${#ACCOUNTS_OK[@]} -gt 0 ]; then
  echo ""
  echo -e "${GREEN}✅ Cuentas completas:${NC}"
  report ""
  report "Cuentas completas:"
  for acc in "${ACCOUNTS_OK[@]}"; do
    echo "   ✅ $acc"
    report "   ✅ $acc"
  done
fi

if [ ${#ACCOUNTS_INCOMPLETE[@]} -gt 0 ]; then
  echo ""
  echo -e "${RED}❌ Cuentas incompletas:${NC}"
  report ""
  report "Cuentas incompletas:"
  for acc in "${ACCOUNTS_INCOMPLETE[@]}"; do
    echo "   ❌ $acc"
    report "   ❌ $acc"
  done
fi

echo ""
echo -e "📄 Reporte completo guardado en: ${BOLD}$REPORT_FILE${NC}"
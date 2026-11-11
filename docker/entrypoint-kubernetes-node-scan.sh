#!/bin/bash
set -eo pipefail

rootfs=/mnt/rootfs
skipMalwareScan=false
skipVulnScan=false
clamavDBDirectory=/var/lib/accuknox-omni/clamav
artifactAPISkipTLSVerification=false
repoSkipTLSVerification=false
repoUsePlainHTTP=false
packageInventory=false
forwardArgs=()

while (($# > 0)); do
  case "$1" in
    --package-inventory|--package-inventory=true)
      packageInventory=true
      forwardArgs+=("$1")
      ;;
    --package-inventory=*)
      if [[ $1 == --package-inventory=true ]]; then
        packageInventory=true
      fi
      forwardArgs+=("$1")
      ;;
    --ai-agent-catalog-path)
      forwardArgs+=("$1")
      if (($# > 1)); then
        forwardArgs+=("$2")
        shift
      fi
      ;;
    --ai-agent-catalog-path=*)
      forwardArgs+=("$1")
      ;;
  esac
  shift
done

if [[ $packageInventory == false && -z "$ARTIFACT_API_ENDPOINT" ]]; then
  echo "env variable ARTIFACT_API_ENDPOINT not set"
  exit 1
fi

if [[ $packageInventory == false && -z "$ARTIFACT_API_TENANT_ID" ]]; then
  echo "env variable ARTIFACT_API_TENANT_ID not set"
  exit 1
fi

if [[ $packageInventory == false && -z "$ARTIFACT_API_LABEL" ]]; then
  echo "env variable ARTIFACT_API_LABEL not set"
  exit 1
fi

if [[ $ARTIFACT_API_SKIP_TLS_VERIFICATION == true || $ARTIFACT_API_SKIP_TLS_VERIFICATION == 1 ]]; then
  artifactAPISkipTLSVerification=true
fi

if [[ -z "$CLUSTER_NAME" ]]; then
  echo "env variable CLUSTER_NAME not set"
  exit 1
fi

if [[ -z "$NODE_NAME" ]]; then
  echo "env variable NODE_NAME not set"
  exit 1
fi

if [[ "$SKIP_MALWARE_SCAN" == "true" || "$SKIP_MALWARE_SCAN" == "1" ]]; then
  skipMalwareScan=true
fi

if [[ "$SKIP_VULN_SCAN" == "true" || "$SKIP_VULN_SCAN" == "1" ]]; then
  skipVulnScan=true
fi

if [[ -z "$VULN_DB_REPOSITORY" ]]; then
  VULN_DB_REPOSITORY="ghcr.io/aquasecurity/trivy-db"
fi

if [[ -z $MSRC_DB_REPOSITORY ]]; then
  MSRC_DB_REPOSITORY="public.ecr.aws/k9v9d5v2/msrc-db"
fi

if [[ -z $CLAMAV_DB_REPOSITORY ]]; then
  CLAMAV_DB_REPOSITORY="public.ecr.aws/k9v9d5v2/clamav-db"
fi

if [[ $REPOSITORY_SKIP_TLS_VERIFICATION == true || $REPOSITORY_SKIP_TLS_VERIFICATION == 1 ]]; then
  repoSkipTLSVerification=true
fi

if [[ $REPOSITORY_PLAIN_HTTP == true || $REPOSITORY_PLAIN_HTTP == 1 ]]; then
  repoUsePlainHTTP=true
fi

if [[ $packageInventory == false && $skipMalwareScan == false ]]; then
  echo "[*] Downloading ClamAV DB"
  omni db download clamav \
    --clamav-db-repository="$CLAMAV_DB_REPOSITORY" \
    --skip-tls-verification=$repoSkipTLSVerification \
    --plain-http=$repoUsePlainHTTP
fi

if [[ $packageInventory == false && $skipVulnScan == false ]]; then
  if [[ -z $OS ]]; then
    echo "[*] Downloading Vuln & MSRC DB"
    omni db download vuln msrc \
      --vuln-db-repository "$VULN_DB_REPOSITORY" \
      --msrc-db-repository "$MSRC_DB_REPOSITORY" \
      --skip-tls-verification=$repoSkipTLSVerification \
      --plain-http=$repoUsePlainHTTP
  fi
  if [[ $OS == linux ]]; then
    echo "[*] Downloading Vuln DB"
    omni db download vuln \
      --vuln-db-repository "$VULN_DB_REPOSITORY" \
      --skip-tls-verification=$repoSkipTLSVerification \
      --plain-http=$repoUsePlainHTTP
  fi
  if [[ $OS == windows ]]; then
    echo "[*] Downloading MSRC DB"
    omni db download msrc \
      --msrc-db-repository "$MSRC_DB_REPOSITORY" \
      --skip-tls-verification=$repoSkipTLSVerification \
      --plain-http=$repoUsePlainHTTP
  fi
fi

echo "[*] Starting Omni"
omni agent scan "$rootfs" \
  --artifact-endpoint="$ARTIFACT_API_ENDPOINT" \
  --skip-tls-verification=$artifactAPISkipTLSVerification \
  --tenant-id="$ARTIFACT_API_TENANT_ID" \
  --artifact-label="$ARTIFACT_API_LABEL" \
  --artifact-token-file=/etc/accuknox-omni/artifact.tok \
  --skip-malware-scan=$skipMalwareScan --skip-vuln-scan=$skipVulnScan \
  --clamav-db-directory=$clamavDBDirectory \
  --override-hostname="${CLUSTER_NAME}/${NODE_NAME}" \
  --platform=kubernetes \
  --vm-uri-prefix="${CLUSTER_NAME}://" \
  "${forwardArgs[@]}"

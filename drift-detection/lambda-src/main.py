import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import boto3


logger = logging.getLogger()
logger.setLevel(logging.INFO)

ssm_client = boto3.client('ssm')
s3_client = boto3.client('s3')

ssm_parameter_arn = os.environ['KOSLI_API_TOKEN_SSM_PARAMETER_ARN']

try:
    response = ssm_client.get_parameter(Name=ssm_parameter_arn, WithDecryption=True)
    kosli_api_token = response['Parameter']['Value']
except Exception as e:
    logger.error(f"Error retrieving SSM parameter: {e}")
    raise

WORKDIR = Path('/tmp/kosli-paths')
PATHS_FILE_NAME = os.environ['PATHS_FILE']
PATHS_FILE_SRC = Path(__file__).parent / PATHS_FILE_NAME

# Files written to S3 more recently than this may not have been attested to
# Kosli yet (the pipelines write the file first, then attest it). Reporting
# such a file would flag the environment as non-compliant, so we skip the
# whole snapshot and let the next scheduled run report it instead.
MIN_ARTIFACT_AGE_SECONDS = int(os.environ.get('MIN_ARTIFACT_AGE_SECONDS', '180'))


def parse_paths_file(text):
    # Minimal parser for the fixed paths-file schema:
    #   version: 1
    #   artifacts:
    #     <name>:
    #       path: <s3-key>
    paths = []
    in_artifacts = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith('#'):
            continue
        if not line.startswith(' '):
            in_artifacts = line.strip() == 'artifacts:'
            continue
        if not in_artifacts:
            continue
        m = re.match(r'\s+path:\s*(.+?)\s*$', line)
        if m:
            paths.append(m.group(1).strip().strip('"').strip("'"))
    return paths


def lambda_handler(event, context):
    bucket = os.environ['S3_BUCKET_NAME']
    env_name = os.environ['KOSLI_ENVIRONMENT_NAME']

    WORKDIR.mkdir(parents=True, exist_ok=True)

    paths_file_dst = WORKDIR / PATHS_FILE_NAME
    paths_file_dst.write_bytes(PATHS_FILE_SRC.read_bytes())

    keys = parse_paths_file(PATHS_FILE_SRC.read_text())
    if not keys:
        logger.error("No artifact paths found in %s", PATHS_FILE_SRC)
        return {"statusCode": 500, "body": "No artifact paths in paths-file"}

    for key in keys:
        local = WORKDIR / key
        local.parent.mkdir(parents=True, exist_ok=True)
        logger.info("downloading s3://%s/%s -> %s", bucket, key, local)
        # get_object (not download_file) so that LastModified describes the
        # same bytes we fingerprint, avoiding a check-then-download race.
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        age = (datetime.now(timezone.utc) - obj['LastModified']).total_seconds()
        if age < MIN_ARTIFACT_AGE_SECONDS:
            msg = (
                f"s3://{bucket}/{key} was modified {age:.0f}s ago "
                f"(< {MIN_ARTIFACT_AGE_SECONDS}s); its attestation may not have "
                "landed yet. Skipping this snapshot; the next run will report it."
            )
            logger.warning(msg)
            return {"statusCode": 200, "body": msg}
        local.write_bytes(obj['Body'].read())

    env = os.environ.copy()
    env['KOSLI_API_TOKEN'] = kosli_api_token

    cmd = [
        '/opt/kosli', 'snapshot', 'paths', env_name,
        f'--paths-file=./{PATHS_FILE_NAME}',
    ]
    logger.info("running: %s (cwd=%s)", ' '.join(cmd), WORKDIR)
    result = subprocess.run(
        cmd,
        cwd=str(WORKDIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout = result.stdout.decode('utf-8')
    stderr = result.stderr.decode('utf-8')
    if stdout:
        logger.info(stdout)
    if stderr:
        logger.error(stderr)

    if result.returncode != 0:
        return {"statusCode": 500, "body": stderr or "kosli command failed"}
    return {"statusCode": 200, "body": stdout}

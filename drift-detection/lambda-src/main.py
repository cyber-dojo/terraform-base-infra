import logging
import os
import re
import subprocess
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
        s3_client.download_file(bucket, key, str(local))

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

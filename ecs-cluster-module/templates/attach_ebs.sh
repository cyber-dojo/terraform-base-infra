#!/bin/bash

set -e

# Send the log output from this script to user-data.log, syslog, and the console
# From: https://alestic.com/2010/12/ec2-user-data-output/
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

yum install unzip -y
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install

INSTANCE_ID=$(ec2-metadata -i | awk '{print $2}')

# Wait until volume is available, then mount it to ec2
EBS_STATE=$(/usr/local/bin/aws ec2 describe-volumes --volume-ids ${VOLUME_ID} --query 'Volumes[*].[State]' --output text)
while [ "$EBS_STATE" != "available" ]
do
    echo "EBS ${VOLUME_ID} is in use, wait 10 seconds..."
    sleep 10
    EBS_STATE=$(/usr/local/bin/aws ec2 describe-volumes --volume-ids ${VOLUME_ID} --query 'Volumes[*].[State]' --output text)
done
# Mount EBS
echo "EBS ${VOLUME_ID} is available, attaching it to ec2..."
/usr/local/bin/aws ec2 attach-volume --volume-id ${VOLUME_ID} --instance-id $INSTANCE_ID --device xvdf
mkdir /ebs_data
sleep 10
mount /dev/nvme1n1 /ebs_data
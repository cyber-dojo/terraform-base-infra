#!/bin/bash

# Set up EFS
systemctl enable --now amazon-ecs-volume-plugin

# Set up ECS config and stert ecs-agent
sudo cp /usr/lib/systemd/system/ecs.service /etc/systemd/system/ecs.service
sudo sed -i '/After=cloud-final.service/d' /etc/systemd/system/ecs.service
sudo systemctl daemon-reload
sudo tee -a /etc/ecs/ecs.config > /dev/null <<EOF
ECS_CLUSTER=${ECS_CLUSTER}
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_AWSVPC_BLOCK_IMDS=true
ECS_ENGINE_TASK_CLEANUP_WAIT_DURATION=30m
ECS_ENABLE_SPOT_INSTANCE_DRAINING=true
ECS_SELINUX_CAPABLE=true
ECS_CONTAINER_INSTANCE_TAGS=${ECS_CONTAINER_INSTANCE_TAGS}
EOF
sudo systemctl start ecs


#!/bin/bash
sudo mkdir -p /opt/aws/amazon-cloudwatch-agent/etc/
sudo rm -rf /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
sudo tee -a /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json > /dev/null <<EOF
{
  "agent": {
    "metrics_collection_interval": 10
  },
  "metrics": {
    "metrics_collected": {
      "disk": {
        "resources": ["/", "/tmp"],
        "measurement": ["disk_used_percent"],
        "ignore_file_system_types": ["sysfs", "devtmpfs"]
      },
      "mem": {
        "measurement": [
          "mem_used_percent"
        ]
      },
      "swap": {
        "measurement": [
          "swap_used_percent"
        ]
      }
    },
    "aggregation_dimensions": [["InstanceId", "InstanceType"], ["InstanceId"]]
  }
}
EOF
sudo systemctl enable amazon-cloudwatch-agent
sudo systemctl start amazon-cloudwatch-agent

This repo is used to create base infrastructure for the cyber-dojo project. 
Pushing changes to the master branch will trigger the beta env infra deployment; merging checges to the prod branch - triggers the prod infra deployment.

# EC2 nodes monitoring
We use [Monit](https://mmonit.com/monit/) tool to monitor basic node metrics (free disc space, RAM, CPU). Alerts are sent to the Slack channel #cyber-dojo-alerts. 
We are using the [ecs-optimised image](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html), that has no Monit preinstalled, so the process of setting up Monit alerts is automated and run on the EC2 startup (see ecs-cluster-module/templates/monit_setup.sh file).

# Docker cleanup automation
[docker-gc](https://github.com/spotify/docker-gc) tool is used to clean up unused docker images on the node (that were exited more than 5 days ago by default), so we don't run out of free space. We use cron job to run the cleanup script. It is configured on the node startup  (see ecs-cluster-module/templates/docker_cleanup.sh file).

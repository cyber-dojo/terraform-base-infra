#!/bin/bash

cat > /root/docker_cleanup.sh << EOF
#!/bin/sh
set -x

docker run --rm --privileged -v /var/run/docker.sock:/var/run/docker.sock -v /etc:/etc:ro -e GRACE_PERIOD_SECONDS=${DOCKER_GC_GRACE_PERIOD_SECONDS} spotify/docker-gc
EOF

chmod +x /root/docker_cleanup.sh

cat > /var/spool/cron/root << EOF
# Cleanup once a day
0 0 * * * /root/docker_cleanup.sh > /root/cron_root.log 2>&1
EOF
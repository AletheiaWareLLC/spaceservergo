#!/bin/bash
#
# Copyright 2019-2020 Aletheia Ware LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -x

read -p 'Username: ' USERNAME
read -p -s 'Password: ' PASSWORD
read -p 'Company' COMPANY
read -p 'Domain Name: ' DOMAIN
read -p 'Stripe Country: ' STRIPE_COUNTRY
read -p 'Stripe Currency: ' STRIPE_CURRENCY
read -p 'Stripe Publishable Key: ' STRIPE_PUBLISHABLE_KEY
read -p 'Stripe Secret Key: ' STRIPE_SECRET_KEY
read -p 'Stripe Storage Product Id: ' STRIPE_STORAGE_PRODUCT_ID
read -p 'Stripe Storage Plan Id: ' STRIPE_STORAGE_PLAN_ID
read -p 'Storage Price Per GB: ' STORAGE_PRICE_PER_GB
read -p 'Stripe Webhook Secret Key: ' STRIPE_WEB_HOOK_SECRET_KEY

# FIXME if user already exists
# Create user
adduser ${USERNAME}

# Add user to sudoers
usermod -aG sudo ${USERNAME}

# Become the new user
su - ${USERNAME}

# Update
sudo apt update

# Upgrade
sudo apt upgrade -y

# Install dependancies
sudo apt install certbot rsync ufw

# Allow http port
sudo ufw allow 80

# Allow https port
sudo ufw allow 443

# Allow space ports
sudo ufw allow 22022 # connect port
sudo ufw allow 22222 # get block port
sudo ufw allow 22322 # get head port
sudo ufw allow 23232 # broadcast port

# Enable firewall
sudo ufw enable

# Generate certificate
sudo certbot certonly --standalone -d ${DOMAIN}

# Allow spaceservergo to read security credentials
sudo chown -R ${USERNAME}:${USERNAME} /etc/letsencrypt/

# Add cron job to renew certificate on the first day of the week
(sudo crontab -l ; echo '* * * * 0 sudo certbot renew --pre-hook "systemctl stop space" --post-hook "systemctl start space"') | sudo crontab -

# Create space directory
mkdir -p /home/${USERNAME}/space/

# Move into directory
cd /home/${USERNAME}/space/

# Download server binary
curl -OL https://github.com/AletheiaWareLLC/spaceservergo/releases/latest/download/spaceservergo-linux-amd64

# Download website content
curl -OL https://github.com/AletheiaWareLLC/spaceservergo/releases/latest/download/html.zip

# Extract zip
unzip html.zip

# Delete zip
rm html.zip

# Initialize Space
ALIAS=${DOMAIN} PASSWORD=${PASSWORD} ROOT_DIRECTORY=~/space/ ./spaceservergo-linux-amd64 init

# Register as Registrar
ALIAS=${DOMAIN} PASSWORD=${PASSWORD} ROOT_DIRECTORY=~/space/ ./spaceservergo-linux-amd64 register-registrar ${DOMAIN} ${STRIPE_COUNTRY} ${STRIPE_CURRENCY} ${STRIPE_PUBLISHABLE_KEY} ${STRIPE_STORAGE_PRODUCT_ID} ${STRIPE_STORAGE_PLAN_ID} ${STORAGE_PRICE_PER_GB}

# Allow spaceservergo to bind to port 443 (HTTPS)
# This is required each time the server binary is updated
sudo setcap CAP_NET_BIND_SERVICE=+eip /home/${USERNAME}/space/spaceservergo-linux-amd64

# Create space config
cat <<EOT >> /home/${USERNAME}/space/config
COMPANY=${COMPANY}
STRIPE_COUNTRY=${STRIPE_COUNTRY}
STRIPE_CURRENCY=${STRIPE_CURRENCY}
STRIPE_PUBLISHABLE_KEY=${STRIPE_PUBLISHABLE_KEY}
STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}
STRIPE_STORAGE_PRODUCT_ID=${STRIPE_STORAGE_PRODUCT_ID}
STRIPE_STORAGE_PLAN_ID=${STRIPE_STORAGE_PLAN_ID}
STRIPE_WEB_HOOK_SECRET_KEY=${STRIPE_WEB_HOOK_SECRET_KEY}
ALIAS=${DOMAIN}
PASSWORD='${PASSWORD}'
ROOT_DIRECTORY=/home/${USERNAME}/space/
CERTIFICATE_DIRECTORY=/etc/letsencrypt/live/${DOMAIN}/
LIVE=true
EOT
chmod 600 /home/${USERNAME}/space/config

# Create space service
sudo cat <<EOT >> /etc/systemd/system/space.service
[Unit]
Description=Space Server
[Service]
User=${USERNAME}
WorkingDirectory=/home/${USERNAME}/space
EnvironmentFile=/home/${USERNAME}/space/config
ExecStart=/home/${USERNAME}/space/spaceservergo-linux-amd64 start
SuccessExitStatus=143
TimeoutStopSec=10
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOT

# Reload daemon
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable space

# Start service
sudo systemctl start space

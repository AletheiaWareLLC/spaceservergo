spaceservergo
=============

This is a Go implementation of a Space Server - end-to-end encrypted, blockchain-backed, data storage.

Build
=====

    go build

Setup
=====

This guide will demonstrate how to setup Space on a remote server, such as a Digital Ocean Droplet running Ubuntu 18.04 x64.

Create a new droplet and ssh into the IP address

    ssh root@your_server_ip

Firewall (UFW)

    # Install firewall
    apt install ufw
    # Allow space ports
    ufw allow 22222
    ufw allow 22322
    ufw allow 23232
    # Enable firewall
    ufw enable

HTTPS (Let's Encrypt)

    # Install certbot
    apt install certbot
    certbot certonly --standalone -d your_server_domain

Stripe

    # Setup a stripe account
    # Create a product (Remote Mining Service)
    # Create a plan (RMS pricing plan eg $0.10 per megabyte)

Space

    # Create space user
    adduser your_server_alias
    # Create space directory
    mkdir -p /home/your_server_alias/space/

    # From your development machine
    # Copy server binary
    rsync $GOPATH/bin/spaceservergo-linux-amd64 your_server_alias@your_server_ip:~/space/
    # Copy website content
    rsync -r $GOPATH/src/github.com/AletheiaWareLLC/spaceservergo/html your_server_alias@your_server_ip:~/space/
    # Copy client binaries into website static content
    rsync $GOPATH/bin/spaceclientgo-* your_server_alias@your_server_ip:~/space/html/static/

    # Initialize Space
    ALIAS=your_server_alias CACHE=~/space/cache/ KEYSTORE=~/space/keys/ LOGSTORE=~/space/logs/ ~/space/html/static/spaceclient-linux-amd64 init

    # Allow spaceservergo to bind to port 443 (HTTPS)
    # This is required each time the server binary is updated
    setcap CAP_NET_BIND_SERVICE=+eip /home/your_server_alias/space/spaceservergo-linux-amd64

Service (Systemd)

    # Create space config
    cat > /home/your_server_alias/space/config <<EOF
    >STRIPE_PUBLISHABLE_KEY=VVVVVV
    >STRIPE_SECRET_KEY=WWWWWW
    >STRIPE_PRODUCT_ID=XXXXXX
    >STRIPE_PLAN_ID=YYYYYY
    >STRIPE_WEB_HOOK_SECRET_KEY=ZZZZZZ
    >ALIAS=your_server_alias
    >PASSWORD='VWXYZ'
    >CACHE=cache/
    >KEYSTORE=keys/
    >LOGSTORE=logs/
    >SECURITYSTORE=/etc/letsencrypt/live/your_server_domain/
    >PEERS=space.aletheiaware.com,bc.aletheiaware.com
    >EOF

    # Create space service
    cat > /etc/systemd/system/space.service <<EOF
    >[Unit]
    >Description=Space Server
    >[Service]
    >User=your_server_alias
    >WorkingDirectory=/home/your_server_alias/space
    >EnvironmentFile=/home/your_server_alias/space/config
    >ExecStart=/home/your_server_alias/space/spaceservergo-linux-amd64
    >SuccessExitStatus=143
    >TimeoutStopSec=10
    >Restart=on-failure
    >RestartSec=5
    >[Install]
    >WantedBy=multi-user.target
    >EOF
    # Reload daemon
    systemctl daemon-reload
    # Start service
    systemctl start space
    # Monitor service
    journalctl -u space

[Unit]
Description=Check network connection and reboot on failure
After=network.target wg-quick@warp.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/check_and_reboot.sh
RemainAfterExit=yes
StandardOutput=journal

[Install]
WantedBy=multi-user.target

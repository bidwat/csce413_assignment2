#!/usr/bin/env bash
set -euo pipefail

# Prepare sshd runtime dir
mkdir -p /run/sshd

# Generate host keys if missing
ssh-keygen -A >/dev/null 2>&1 || true

# Create a demo user
if ! id knockuser >/dev/null 2>&1; then
  useradd -m -s /bin/bash knockuser
fi
echo "knockuser:knockme" | chpasswd

# Ensure password auth is enabled (for demo)
if grep -q "^#PasswordAuthentication" /etc/ssh/sshd_config; then
  sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
elif grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
  sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
else
  echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
fi

# Start SSH on protected port 2222
/usr/sbin/sshd -p 2222

# Start port knocking server (foreground)
exec python3 /app/knock_server.py

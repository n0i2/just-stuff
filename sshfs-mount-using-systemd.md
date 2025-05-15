The following guide demonstrates how to use `systemd` to automatically mount a remote Hetzner StorageBox destination using SSHFS and start the `qbittorrent-nox` service after a system reboot. This addresses the issue where qbittorrent-nox fails to load torrents if the mount isn't ready. By using systemd to ensure the filesystem is mounted before starting qbittorrent-nox, everything runs smoothly.

#### **Ensure SSHFS Mount is Ready Before Starting `qbittorrent-nox`**

Instead of relying on systemd’s default mount behavior, you can explicitly add a **wait** mechanism before starting `qbittorrent-nox`.

#### Use `systemd.mount` for SSHFS

First, ensure the SSHFS mount is managed by systemd, and explicitly mark it as a dependency for the `qbittorrent-nox` service:

1. **Create a Custom Systemd Mount Unit for SSHFS**:

   If the mount isn’t already managed by systemd, you can create a custom `.mount` unit for SSHFS. This way, you can ensure the mount is properly handled before starting the service.

   Create a new mount unit file, `/etc/systemd/system/mnt-hetzner.mount`, with the following content **(modify accordingly with your `qbittorrent-nox` UID and GID)**:

```
[Unit]
Description=SSHFS Mount for Hetzner Storage Box
After=network.target

[Mount]
What=username@username.your-storagebox.de:/path/to/your/files
Where=/desired/path/to/mount
Type=fuse.sshfs
Options=IdentityFile=/path/to/ssh-private-key,port=23,reconnect,ServerAliveInterval=15,uid=1001,gid=114,users,allow_other
TimeoutSec=30

[Install]
WantedBy=multi-user.target
```

This unit defines the SSHFS mount explicitly for systemd and will wait for it to complete before proceeding.

2. **Enable the Mount Unit**:
   
   Enable the SSHFS mount unit to ensure it starts automatically at boot:
   `sudo systemctl enable mnt-hetzner.mount`

4. **Ensure `qbittorrent-nox.service` starts after the SSHFS mount is fully establised:**
   
   Edit the `qbittorrent-nox` service again with the following command:
   `sudo systemctl edit qbittorrent-nox.service`
   
   Add or modify the `[Unit]` section as follows:
```
[Unit]
After=mnt-hetzner.mount
Requires=mnt-hetzner.mount
```

4. **Reload systemd**:
   `sudo systemctl daemon-reload`

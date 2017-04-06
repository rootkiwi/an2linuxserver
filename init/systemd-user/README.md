# Systemd user unit
### I use archlinux and this service unit works for me

#### Tips if it does not work for you
- You may need to:
`loginctl enable-linger <your-username>`

- Info about systemd/user: https://wiki.archlinux.org/index.php/Systemd/User


#### Instructions:
1. Change `ExecStart=`

2. Put *an2linux.service* here:
`~/.config/systemd/user/an2linux.service`

2. Run `systemctl --user daemon-reload`

#### Start:
`systemctl --user start an2linux.service`

#### Stop:
`systemctl --user stop an2linux.service`

#### Autostart:
`systemctl --user enable an2linux.service`

#### Status:
`systemctl --user status an2linux.service`

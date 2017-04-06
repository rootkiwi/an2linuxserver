# Systemd system unit
### I use archlinux and this service unit works for me

#### Tips if it does not work for you
- `ReadWritePaths` may be named `ReadWriteDirectories` in systemd < 231

- The `DBUS_SESSION_BUS_ADDRESS` environment variable may be different for you,
and maybe even different every reboot

##### For bluetooth I've tried

```
Wants=bluetooth.service
After=bluetooth.service

Also with Requires= instead of Wants= and with bluetooth.target instead
of .service
```

That worked 50% of the time, the other 50% it resulted in:
`bluetooth.btcommon.BluetoothError: (2, 'No such file or directory')`

With `systemctl status an2linux.service bluetooth.service`
I could see that even with `After=` etc an2linux.service still started one
second before bluetooth.service.

Some systemd expert may know what I'm doing wrong.

A workaround that worked for me was `ExecStartPre=/usr/bin/sleep 3`.

So this problem is only with this system-wide systemd unit if using bluetooth.

## Instructions:
1. Change `User=` and `Group=`

2. Change `ExecStart=`

3. Uncomment `Wants=`, `After=` and `ExecStartPre=` if you want to use workaround for bluetoth

4. Put *an2linux.service* here:
`/etc/systemd/system/an2linux.service`

5. Run `systemctl daemon-reload`

#### Start:
`systemctl start an2linux.service`

#### Stop:
`systemctl stop an2linux.service`

#### Autostart:
`systemctl enable an2linux.service`

#### Status:
`systemctl status an2linux.service`

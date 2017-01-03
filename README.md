# AN2Linux - server
Sync android notifications encrypted to a linux desktop with tcp or bluetooth.

This is the server part of AN2Linux.

[Link to client part](https://github.com/rootkiwi/an2linuxclient/)

## About
AN2Linux is my first (not tiny) program / app and I've been working on it for
quite some time now.
I wanted to make an2linux because it was something I needed and also to learn.

It's been a fun ride, I have learned a lot.

But be warned, there may be many bugs / problems. If you see something
that is bad please tell me why and not just that it sucks.

## Dependencies
I'm using archlinux but I've added here what I think to be the package
names for debian/ubuntu as well.

* **python (3.4+)**
```
Arch: python
Debian / Ubuntu: python3
```

* **libnotify**
```
Arch: libnotify
Debian / Ubuntu: libnotify4 gir1.2-notify-0.7
```

* **python-gobject**
```
Arch: python-gobject
Debian / Ubuntu: python3-gi
```

* **openssl (1.0.1+)**

### For bluetooth:
* **python-pip**
```
Arch: python-pip
Debian / Ubuntu: python3-pip
```

* **PyBluez**
```
pip3 install pybluez
```

## How to use
First time just run *an2linuxserver.py* and follow the instructions.

AN2Linux uses TLS for encryption with both client and server authentication.
That means that the client (android) and the server (your computer)
need to exchange certificates first.

To initiate pairing you must have *an2linuxserver.py* running and then in the
android app press initiate pairing when in the process of adding a new server.

### For bluetooth:
First you need to pair your phone and computer with each other (the normal
bluetooth pairing), and then do the certificate exchange as explained above.

Why use TLS over bluetooth when it's already encrypted?

Well, firstly, because I wanted to try :)

And secondly, from the little I've read about bluetooth it seems that the
encryption key size negotiated can be very small.

#### PyBluez:
I'm using archlinux so I'm going to tell you have it works for me, I have no
idea how it works on other distros. It may work out of the box, just try it.

This is the error I get without the fixes below:<br>
*bluetooth.btcommon.BluetoothError: (13, 'Permission denied')*

So, if you're not using archlinux but still systemd and get an error like
that maybe you should try something similar.

#### Edit file:
*/usr/lib/systemd/system/bluetooth.service*

#### Make the changes in an override file:
```
systemctl edit bluetooth.service
```

#### Add the following lines:
````
[Service]
ExecStart=
ExecStart=/usr/lib/bluetooth/bluetoothd -C
ExecStartPost=/bin/chmod 662 /var/run/sdp
```

#### then apply changes:
```
systemctl daemon-reload
systemctl restart bluetooth.service
```

More info about this problem:
https://bbs.archlinux.org/viewtopic.php?id=201672.

## Run in background:
You could just run an2linux in its own terminal window but maybe you want
to have it run in background somehow and maybe to autostart.

There are many different ways to do that.

You could use screen/tmux or a systemd service.<br>
The great thing about screen/tmux is that you can attach to it if needed.

#### With tmux you could use something like this:
```
tmux new -d -s an2linux '<path_to_an2linuxserver.py>'
```

#### Example user systemd service:
*~/.config/systemd/user/an2linux.service*
```
[Unit]
Description=AN2Linux server

[Service]
Type=simple
StandardOutput=null
Restart=on-failure
ExecStart=<path_to_an2linuxserver.py>

[Install]
WantedBy=default.target
```

#### Or you could combine tmux with a systemd service:
*~/.config/systemd/user/an2linux_tmux.service*
```
[Unit]
Description=AN2Linux server tmux

[Service]
Type=forking
Restart=on-failure
ExecStart=/usr/bin/tmux new -d -s an2linux '<path_to_an2linuxserver.py>'
ExecStop=/usr/bin/tmux kill-session -t an2linux

[Install]
WantedBy=default.target
```

#### Start:
```
systemctl --user start an2linux.service
```

#### Stop:
```
systemctl --user stop an2linux.service
```

#### Autostart:
```
systemctl --user enable an2linux.service
```

#### Status:
```
systemctl --user status an2linux.service
```

## License
[GNU General Public License 3](https://www.gnu.org/licenses/gpl-3.0.html),
with the additional special 
exception to link portions of this program with the OpenSSL library.

See LICENSE for more details.

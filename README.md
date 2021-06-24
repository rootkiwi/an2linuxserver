# AN2Linux - server
Sync Android notifications encrypted using TLS to a Linux desktop over WiFi, Mobile data or Bluetooth.

This is the server part of AN2Linux which will run on your computer.

The Android app can be found here: [https://github.com/rootkiwi/an2linuxclient/](https://github.com/rootkiwi/an2linuxclient/)

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
Debian / Ubuntu: libnotify4 gir1.2-notify-0.7 gir1.2-gdkpixbuf-2.0
```

* **python-gobject**
```
Arch: python-gobject
Debian / Ubuntu: python3-gi
```

* **openssl (1.0.1+)**


## Dependencies for bluetooth

* **BlueZ dev files**
```
Arch: bluez-libs
Debian / Ubuntu: libbluetooth-dev
```

* **PyBluez** with normal package manager
```
Arch: python-pybluez
Debian / Ubuntu: python3-bluez
```


* **PyBluez** or with pip
```
Arch: python-pip
Debian / Ubuntu: python3-pip

pip3 install pybluez
```

## How to use
First time just run `an2linuxserver.py` and follow the instructions.

AN2Linux uses TLS for encryption with both client and server authentication.
That means that the client (android) and the server (your computer)
need to exchange certificates first.

To initiate pairing you must have `an2linuxserver.py` running and then in the
android app press initiate pairing when in the process of adding a new server.

### For bluetooth
First you need to pair your phone and computer with each other (the normal
bluetooth pairing), and then do the certificate exchange as explained above.

Why use TLS over bluetooth when bluetooth is already encrypted?

Well, firstly, because I wanted to try :)

And secondly, from the little I've read about bluetooth it seems that the
encryption key size negotiated can be very small.

#### PyBluez not working?
I'm using archlinux so I'm going to tell you how it works for me, I have no
idea how it works on other distros. It may work out of the box or it may not, just try it.

This is the error I get without the fixes below:<br>
`bluetooth.btcommon.BluetoothError: (13, 'Permission denied')`

So, if you're not using archlinux but still are using systemd and get an error like
that maybe you should try something similar.

#### Edit bluetooth.service in an override file
```
systemctl edit bluetooth.service
```

#### Add the following lines
```
[Service]
ExecStart=
ExecStart=/usr/lib/bluetooth/bluetoothd -C
ExecStartPost=/bin/chmod 662 /var/run/sdp
```

#### then apply changes
```
systemctl daemon-reload
systemctl restart bluetooth.service
```

More info about this problem:
https://bbs.archlinux.org/viewtopic.php?id=201672.

## Config directory
First time when running `an2linuxserver.py` it will create the directory:
`$XDG_CONFIG_HOME/an2linux/`.

If `$XDG_CONFIG_HOME` is not set it defaults to: `$HOME/.config/an2linux/`.

In this config directory a few files will be created.

#### Config file
A default config file named `config` will be created with the settings:
- `tcp_server` **[on/off]** *default:* **on**
- `tcp_port` **[0-65535]** *default:* **46352**
- `bluetooth_server` **[on/off]** *default:* **off**
- `bluetooth_support_kitkat` **[on/off]** *default:* **off**
- `notification_timeout` **[integer]** *default:* **5**
- `list_size_duplicates` **[0-50]** *default:* **0**
- `ignore_duplicates_list_for_titles` **[comma-separated list]** *default:* **AN2Linux, title**
- `keywords_to_ignore` **[comma-separated list]** *default:* **''**

Open that config file for more detailed info about every setting.

#### Server RSA key and certificate
AN2Linux will generate a 4096 bit RSA key `rsakey.pem`  and a self-signed certificate `certificate.pem`.

Just delete those and restart AN2Linux if you want to generate a new key and certificate.

#### Trusted certificates
After a successful certificate exchange AN2linux will create a file named
`authorized_certs`.

Every line in that file will represent a trused certificate.

It will be in the format `SHA256:<certificate_fingerprint> <trused_certificate>`.

That first part `SHA256...` is not used by AN2linux at all, it's just
added as a convenience to the user to help distinguish between multiple certificates.

#### Diffie–Hellman ephemeral
If the setting `bluetooth_support_kitkat` is turned `on` AN2linux will also generate a file named `dhparam.pem`.

That is because [SSLEngine](https://developer.android.com/reference/javax/net/ssl/SSLEngine.html) does not support any
[ECDHE](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman) cipher suites
until from API 20+ (Android 5.0+).

## Run AN2Linux as a service
[Init/Service scripts](https://github.com/rootkiwi/an2linuxserver/tree/master/init)

## Security with a firewall
a popular easy-to-use firewall for Linux is Uncomplicated Firewall (ufw)

1. install it:
    - on Arch: $ `sudo pacman -S ufw`
    - on Debian/Ubuntu: $ `sudo apt-get install ufw`
2. start and enable ufw’s systemd unit:
    - $ `sudo systemctl start ufw; sudo systemctl enable ufw`
3. set your mobile device's LAN ip to a static ip
    - in the WiFi settings, long press the network you're connected to and tap "modify network"
    - if authentication is required (it should) and you're authenticated already leave the password feild empty
    - (Google it for the rest of steps, which depend on your region/router for the Gateway address)
4. allow traffic limited to one port, from your mobile device's LAN static ip
    - $ `sudo ufw allow from <your-mobile-device's-LAN-static-ip> to any port <your-config-port>`

## License
[GNU General Public License 3](https://www.gnu.org/licenses/gpl-3.0.html),
with the additional special exception to link portions of this program with the OpenSSL library.

See [LICENSE](LICENSE) for more details.

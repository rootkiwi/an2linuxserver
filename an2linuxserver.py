#!/usr/bin/env python3
#
# Copyright 2017 rootkiwi
#
# AN2Linux-server is licensed under GNU General Public License 3, with the additional
# special exception to link portions of this program with the OpenSSL library.
#
# See LICENSE for more details.

import sys
try:
    import ssl
except ImportError as e:
    print('Dependency missing: openssl')
    print(e)
    sys.exit(1)
try:
    import gi
    from gi.repository import GLib
except ImportError as e:
    print('Dependency missing: python-gobject')
    print(e)
    sys.exit(1)
try:
    gi.require_version('Notify', '0.7')
    from gi.repository import Notify
except (ImportError, ValueError) as e:
    print('Dependency missing: libnotify')
    print(e)
    sys.exit(1)
import threading
import datetime
import os
import configparser
import struct
import tempfile
import socketserver
import signal
import shutil
import time
import subprocess
import hashlib
import termios
import base64
import select
from collections import deque


class Notification:

    # this is is a deque of the latest notifications hash to be able to skip duplicates
    latest_notifications = None

    # this is a list of notification titles to ignore latest_notifications list
    titles_that_ignore_latest = None

    '''this is to keep a list of active Notification objects with icons to avoid being garbage collected
    because when a Notification object is garbage collected the TemporaryFile is destroyed
    and atleast with dunst notification daemon with stacked notifications when an icon file
    is removed from filesystem the icon gets removed from all currently visible stacked notifications'''
    active_notifications_with_icons = []

    def __init__(self, title, message, notif_hash, icon_tmp_file=None):
        self.title = title
        self.message = message
        self.notif_hash = notif_hash
        self.icon_tmp_file = icon_tmp_file
        self.icon_path = ''
        if self.icon_tmp_file is not None:
            self.icon_path = icon_tmp_file.name

    def show(self):
        if self.notif_hash not in Notification.latest_notifications or self.title in Notification.titles_that_ignore_latest:
            Notification.latest_notifications.append(self.notif_hash)
            Notify.init('AN2Linux')
            self.notif = Notify.Notification.new(self.title, self.message, self.icon_path)
            self.notif.set_timeout(notification_timeout_milliseconds)
            if self.icon_tmp_file is not None:
                Notification.active_notifications_with_icons.append(self)
                self.notif.connect('closed', self.closed_callback)
            self.notif.show()

    def closed_callback(self, notif_instance):
        self.icon_tmp_file.close()
        Notification.active_notifications_with_icons.remove(self)


class TCPHandler(socketserver.BaseRequestHandler):

    active_pairing_connection = False
    cancel_pairing = False

    def handle(self):
        try:
            conn_type = self.request.recv(1)
            if conn_type == PAIR_REQUEST:
                if not TCPHandler.active_pairing_connection:
                    self.handle_pair_request()
            elif conn_type == NOTIF_CONN:
                self.handle_notification_connection()
        except Exception as e:
            print('Error TCPHandler/handle')
            print(e)

    def handle_pair_request(self):
        TCPHandler.active_pairing_connection = True
        TCPHandler.cancel_pairing = False
        pair_tls_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
        pair_tls_ctx.load_cert_chain(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)
        pair_tls_ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA')
        pair_tls_ctx.set_ecdh_curve('prime256v1')
        pair_tls_ctx.options |= ssl.OP_SINGLE_ECDH_USE

        try:
            tls_socket = pair_tls_ctx.wrap_socket(self.request, server_side=True)
        except ssl.SSLError as ssle:
            TCPHandler.active_pairing_connection = False
            print_with_timestamp('(TCP) Failed TLS handshake pair_request: {}'.format(ssle))
            return

        print_with_timestamp('(TCP) Pair request from: {}\n'.format(self.client_address[0]))

        client_cert_size = struct.unpack('>I', recvall(tls_socket, 4))[0]
        client_cert = recvall(tls_socket, client_cert_size)

        sha1 = hashlib.sha1(client_cert + SERVER_CERT_DER).hexdigest().upper()
        sha1_format = [sha1[x:x + 2] for x in range(0, len(sha1), 2)]

        print('It is very important that you verify that the following hash matches what is viewed on your phone\n'
              'It is a sha1 hash like so: sha1(client_cert + server_cert)\n\n'
              'If the hash don\'t match there could be a man-in-the-middle attack\n'
              'Or something else is not right, you should abort if they don\'t match!\n')
        print(' '.join(sha1_format[:len(sha1_format) // 2]))
        print(' '.join(sha1_format[len(sha1_format) // 2:]))

        self.server_allow_pair = False
        self.client_allow_pair = False

        try:
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
        except Exception:
            pass
        self.user_input_prompt = 'Enter "yes" to accept pairing or "no" to deny: '
        print('\n{}'.format(self.user_input_prompt), end='')

        threading.Thread(target=self.pair_response_thread, args=(tls_socket,)).start()
        while not TCPHandler.cancel_pairing:
            ready = select.select([sys.stdin], [], [], 1)[0]
            if ready:
                user_input = sys.stdin.readline().strip()
                if user_input.casefold() == 'yes'.casefold():
                    tls_socket.sendall(ACCEPT_PAIRING)
                    self.server_allow_pair = True
                    if not self.client_allow_pair:
                        print('Waiting for client response')
                    while not TCPHandler.cancel_pairing:
                        if self.client_allow_pair:
                            add_to_authorized_certs(client_cert)
                            break
                        else:
                            time.sleep(1)
                    break
                elif user_input.casefold() == 'no'.casefold():
                    tls_socket.sendall(DENY_PAIRING)
                    print('Pairing canceled')
                    TCPHandler.cancel_pairing = True
                else:
                    print(self.user_input_prompt, end='', flush=True)

        TCPHandler.active_pairing_connection = False

    def pair_response_thread(self, tls_socket):
        while not TCPHandler.cancel_pairing:
            ready = select.select([tls_socket], [], [], 1)[0]
            if ready:
                client_response = tls_socket.recv(1)
                if client_response == ACCEPT_PAIRING:
                    self.client_allow_pair = True
                    if self.server_allow_pair:
                        print('Client accepted pairing')
                        break
                    else:
                        print('\r{} (Client accepted pairing): '.format(self.user_input_prompt[:-2]), end='')
                        # to notice if socket closed
                        while TCPHandler.active_pairing_connection:
                            ready = select.select([tls_socket], [], [], 1)[0]
                            if ready and tls_socket.recv(1) == b'':
                                if not self.server_allow_pair and not TCPHandler.cancel_pairing:
                                    print('\nSocket closed')
                                break
                        TCPHandler.cancel_pairing = True
                elif client_response == DENY_PAIRING:
                    if self.server_allow_pair:
                        print('Client denied pairing')
                    else:
                        print('\nClient denied pairing')
                    TCPHandler.cancel_pairing = True
                else:
                    if not TCPHandler.cancel_pairing:
                        print('\nSocket closed or recieved something strange')
                        TCPHandler.cancel_pairing = True

    def handle_notification_connection(self):
        try:
            notif_tls_ctx.load_verify_locations(cadata=parse_authorized_certs())
            tls_socket = notif_tls_ctx.wrap_socket(self.request, server_side=True)
        except Exception as e:
            print_with_timestamp('(TCP) Failed TLS handshake notif_conn: {}'.format(e))
            return

        # one recv should not take longer than 10 sec
        tls_socket.settimeout(10)

        notification_flags = struct.unpack('>B', tls_socket.recv(1))[0]

        if notification_flags & FLAG_INCLUDE_TITLE == FLAG_INCLUDE_TITLE:
            include_title = True
        else:
            include_title = False

        if notification_flags & FLAG_INCLUDE_MESSAGE == FLAG_INCLUDE_MESSAGE:
            include_message = True
        else:
            include_message = False

        if notification_flags & FLAG_INCLUDE_ICON == FLAG_INCLUDE_ICON:
            include_icon = True
        else:
            include_icon = False

        title = ''
        message = ''

        if include_title or include_message:
            title_and_or_message_size = struct.unpack('>I', recvall(tls_socket, 4))[0]
            title_and_or_message = recvall(tls_socket, title_and_or_message_size).decode()
            if include_title:
                title = title_and_or_message.split('|||')[0]
            if include_message:
                message = title_and_or_message.split('|||')[1]

        if include_icon:
            icon_tmp_file = tempfile.NamedTemporaryFile(buffering=0, dir=TMP_DIR_PATH)
            icon_size = struct.unpack('>I', recvall(tls_socket, 4))[0]
            icon = recvall(tls_socket, icon_size)
            try:
                icon_tmp_file.write(icon)
                Notification(title, message, hashlib.sha1(title.encode() + message.encode() + icon).digest(),
                             icon_tmp_file).show()
            except Exception:
                Notification(title, message, hashlib.sha1(title.encode() + message.encode()).digest()).show()
        else:
            Notification(title, message, hashlib.sha1(title.encode() + message.encode()).digest()).show()


class ThreadingBluetoothServer:

    def __init__(self):
        self.bluetooth_server_sock = BluetoothSocket(RFCOMM)
        self.bluetooth_server_sock.bind(("", PORT_ANY))
        self.bluetooth_server_sock.listen(1)
        self.port = self.bluetooth_server_sock.getsockname()[1]

        # hardcoded uuid generated from https://www.uuidgenerator.net/
        self.uuid = "a97fbf21-2ef3-4daf-adfb-2a53ffa87b8e"

        advertise_service(self.bluetooth_server_sock, "AN2Linux_bluetooth_server",
                          service_id=self.uuid,
                          service_classes=[self.uuid, SERIAL_PORT_CLASS],
                          profiles=[SERIAL_PORT_PROFILE])

        self.shutdown_request = False

    def serve_forever(self):
        while not self.shutdown_request:
            ready = select.select([self.bluetooth_server_sock], [], [], 1)[0]
            if ready:
                client_sock, client_info = self.bluetooth_server_sock.accept()
                threading.Thread(target=BluetoothHandler, args=(client_sock, client_info[0])).start()

        self.bluetooth_server_sock.close()

    def shutdown(self):
        self.shutdown_request = True


class BluetoothHandler:

    active_pairing_connection = False
    cancel_pairing = False

    def __init__(self, socket, address):
        self.socket = socket
        self.address = address
        self.tls_bio = None
        self.incoming = None
        self.outgoing = None
        self.handle()

    def handle(self):
        try:
            conn_type = self.socket.recv(1)
            if conn_type == PAIR_REQUEST and not BluetoothHandler.active_pairing_connection:
                self.handle_pair_request()
            elif conn_type == NOTIF_CONN:
                self.handle_notification_connection()
        except Exception as e:
            print('Error BluetoothHandler/handle')
            print(e)
        finally:
            self.socket.close()

    def do_handshake(self):
        # incoming <- ClientHello
        client_hello_size = struct.unpack('>I', recvall(self.socket, 4))[0]
        client_hello = recvall(self.socket, client_hello_size)
        self.incoming.write(client_hello)

        # ServerHello..ServerHelloDone -> outgoing
        try:
            self.tls_bio.do_handshake()
        except ssl.SSLWantReadError:
            server_hello = self.outgoing.read()
            server_hello_size = struct.pack('>I', len(server_hello))
            self.socket.sendall(server_hello_size)
            self.socket.sendall(server_hello)

        # incoming <- [client]Certificate*..ClientKeyExchange..Finished
        client_keyexchange_size = struct.unpack('>I', recvall(self.socket, 4))[0]
        client_keyexchange = recvall(self.socket, client_keyexchange_size)
        self.incoming.write(client_keyexchange)

        # ChangeCipherSpec..Finished -> outgoing
        self.tls_bio.do_handshake()
        server_change_cipher_spec = self.outgoing.read()
        server_change_cipher_spec_size = struct.pack('>I', len(server_change_cipher_spec))
        self.socket.sendall(server_change_cipher_spec_size)
        self.socket.sendall(server_change_cipher_spec)

    def tls_read_full_record(self):
        pending = 1
        record = bytearray()
        while pending > 0:
            record.extend(self.tls_bio.read(4096))
            pending = self.tls_bio.pending()
        return record

    def tls_encrypt(self, app_data):
        self.tls_bio.write(app_data)
        return self.outgoing.read()

    def tls_decrypt(self, net_data):
        self.incoming.write(net_data)
        return self.tls_read_full_record()

    def handle_pair_request(self):
        BluetoothHandler.active_pairing_connection = True
        BluetoothHandler.cancel_pairing = False
        pair_tls_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
        pair_tls_ctx.load_cert_chain(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)
        pair_tls_ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA')
        pair_tls_ctx.set_ecdh_curve('prime256v1')
        pair_tls_ctx.options |= ssl.OP_SINGLE_ECDH_USE

        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls_bio = pair_tls_ctx.wrap_bio(incoming=self.incoming, outgoing=self.outgoing, server_side=True)

        try:
            self.do_handshake()
        except ssl.SSLError as ssle:
            BluetoothHandler.active_pairing_connection = True
            print_with_timestamp('(Bluetooth) Failed TLS handshake pair_request: {}'.format(ssle))
            return

        print_with_timestamp('(Bluetooth) Pair request from: {}\n'.format(self.address))

        '''I don't know how else to do this when using SSLEngine/SSL_BIO, I don't see any security
        issue with sending the length of the encrypted data in cleartext, using something like wireshark
        it's possible to see the length anyway'''
        client_cert_size = struct.unpack('>I', recvall(self.socket, 4))[0]
        client_cert_encrypted = recvall(self.socket, client_cert_size)
        client_cert = self.tls_decrypt(client_cert_encrypted)


        sha1 = hashlib.sha1(client_cert + SERVER_CERT_DER).hexdigest().upper()
        sha1_format = [sha1[x:x + 2] for x in range(0, len(sha1), 2)]

        print('It is very important that you verify that the following hash matches what is viewed on your phone\n'
              'It is a sha1 hash like so: sha1(client_cert + server_cert)\n\n'
              'If the hash don\'t match there could be a man-in-the-middle attack\n'
              'Or something else is not right, you should abort if they don\'t match!\n')
        print(' '.join(sha1_format[:len(sha1_format) // 2]))
        print(' '.join(sha1_format[len(sha1_format) // 2:]))

        self.server_allow_pair = False
        self.client_allow_pair = False

        try:
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
        except Exception:
            pass
        self.user_input_prompt = 'Enter "yes" to accept pairing or "no" to deny: '
        print('\n{}'.format(self.user_input_prompt), end='')

        threading.Thread(target=self.pair_response_thread).start()
        while not BluetoothHandler.cancel_pairing:
            ready = select.select([sys.stdin], [], [], 1)[0]
            if ready:
                user_input = sys.stdin.readline().strip()
                if user_input.casefold() == 'yes'.casefold():
                    encrypted = self.tls_encrypt(ACCEPT_PAIRING)
                    encrypted_size = struct.pack('>I', len(encrypted))
                    self.socket.sendall(encrypted_size)
                    self.socket.sendall(encrypted)
                    self.server_allow_pair = True
                    if not self.client_allow_pair:
                        print('Waiting for client response')
                    while not BluetoothHandler.cancel_pairing:
                        if self.client_allow_pair:
                            add_to_authorized_certs(client_cert)
                            break
                        else:
                            time.sleep(1)
                    break
                elif user_input.casefold() == 'no'.casefold():
                    encrypted = self.tls_encrypt(DENY_PAIRING)
                    encrypted_size = struct.pack('>I', len(encrypted))
                    self.socket.sendall(encrypted_size)
                    self.socket.sendall(encrypted)
                    print('Pairing canceled')
                    BluetoothHandler.cancel_pairing = True
                else:
                    print(self.user_input_prompt, end='', flush=True)

        BluetoothHandler.active_pairing_connection = False

    def pair_response_thread(self):
        while not BluetoothHandler.cancel_pairing:
            ready = select.select([self.socket], [], [], 1)[0]
            if ready:
                try:
                    client_response_size = struct.unpack('>I', recvall(self.socket, 4))[0]
                    client_response_encrypted = recvall(self.socket, client_response_size)
                    client_response = self.tls_decrypt(client_response_encrypted)
                except Exception:
                    print('\nSocket closed or recieved something strange')
                    BluetoothHandler.cancel_pairing = True
                    break

                if client_response == ACCEPT_PAIRING:
                    self.client_allow_pair = True
                    if self.server_allow_pair:
                        print('Client accepted pairing')
                        break
                    else:
                        print('\r{} (Client accepted pairing): '.format(self.user_input_prompt[:-2]), end='')
                        # to notice if socket closed
                        while BluetoothHandler.active_pairing_connection:
                            ready = select.select([self.socket], [], [], 1)[0]
                            if ready:
                                try:
                                    self.socket.recv(1)
                                except BluetoothError:
                                    if not self.server_allow_pair and not BluetoothHandler.cancel_pairing:
                                        print('\nSocket closed')
                                    break
                        BluetoothHandler.cancel_pairing = True
                elif client_response == DENY_PAIRING:
                    if self.server_allow_pair:
                        print('Client denied pairing')
                    else:
                        print('\nClient denied pairing')
                    BluetoothHandler.cancel_pairing = True
                else:
                    if not BluetoothHandler.cancel_pairing:
                        print('\nSocket closed or recieved something strange2')
                        BluetoothHandler.cancel_pairing = True

    def handle_notification_connection(self):
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()

        try:
            notif_tls_ctx.load_verify_locations(cadata=parse_authorized_certs())
            self.tls_bio = notif_tls_ctx.wrap_bio(incoming=self.incoming, outgoing=self.outgoing, server_side=True)
            self.do_handshake()
        except Exception as e:
            print_with_timestamp('(Bluetooth) Failed TLS handshake notif_conn: {}'.format(e))
            return

        # one recv should not take longer than 10 sec
        self.socket.settimeout(10)

        notification_flags_size = struct.unpack('>I', recvall(self.socket, 4))[0]
        notification_flags_encrypted = recvall(self.socket, notification_flags_size)
        notification_flags = struct.unpack('>B', self.tls_decrypt(notification_flags_encrypted))[0]

        if notification_flags & FLAG_INCLUDE_TITLE == FLAG_INCLUDE_TITLE:
            include_title = True
        else:
            include_title = False

        if notification_flags & FLAG_INCLUDE_MESSAGE == FLAG_INCLUDE_MESSAGE:
            include_message = True
        else:
            include_message = False

        if notification_flags & FLAG_INCLUDE_ICON == FLAG_INCLUDE_ICON:
            include_icon = True
        else:
            include_icon = False

        title = ''
        message = ''

        if include_title or include_message:
            title_and_or_message_size = struct.unpack('>I', recvall(self.socket, 4))[0]
            title_and_or_message_encrypted = recvall(self.socket, title_and_or_message_size)
            title_and_or_message = self.tls_decrypt(title_and_or_message_encrypted).decode()
            if include_title:
                title = title_and_or_message.split('|||')[0]
            if include_message:
                message = title_and_or_message.split('|||')[1]

        if include_icon:
            icon_tmp_file = tempfile.NamedTemporaryFile(buffering=0, dir=TMP_DIR_PATH)
            icon_size = struct.unpack('>I', recvall(self.socket, 4))[0]
            icon_encrypted = recvall(self.socket, icon_size)
            icon = self.tls_decrypt(icon_encrypted)
            try:
                icon_tmp_file.write(icon)
                Notification(title, message, hashlib.sha1(title.encode() + message.encode() + icon).digest(),
                             icon_tmp_file).show()
            except Exception:
                Notification(title, message, hashlib.sha1(title.encode() + message.encode()).digest()).show()
        else:
            Notification(title, message, hashlib.sha1(title.encode() + message.encode()).digest()).show()


def recvall(socket, size):
    buf = bytearray()
    while len(buf) < size:
        buf.extend(socket.recv(size - len(buf)))
    return buf


def print_with_timestamp(string):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print('[{}] {}'.format(current_time, string))


def generate_server_private_key_and_certificate(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH):
    openssl_process = subprocess.Popen(['openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-nodes', '-sha256',
                                        '-keyout', RSA_PRIVATE_KEY_PATH, '-out', CERTIFICATE_PATH,
                                        '-days', '3650', '-subj', '/CN=an2linuxserver'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stderr = openssl_process.communicate()[1]
    if openssl_process.returncode == 0:
        print_with_timestamp('Generated a 4096 bit RSA private key')
        print_with_timestamp('Key saved to: ' + RSA_PRIVATE_KEY_PATH)
        print_with_timestamp('Certificate saved to: ' + CERTIFICATE_PATH)
    else:
        print_with_timestamp('Error generating private key, exiting..')
        print(stderr)
        sys.exit(1)


def parse_authorized_certs():
    if os.path.isfile(AUTHORIZED_CERTS_PATH):
        # authorized_certs file:
        # sha1(cert_DER).hexdigest() base64.b64encode(cert_DER).decode()
        with open(AUTHORIZED_CERTS_PATH, 'r') as f:
            try:
                authorized_certs = b''.join([base64.b64decode(line.split(' ')[1])
                                 for line in f.readlines() if len(line.split(' ')) == 2])
                # testing if valid certificates
                ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2).load_verify_locations(cadata=authorized_certs)
                return authorized_certs
            except Exception as e:
                print_with_timestamp('Corrupted authorized_certs file: {}'.format(e))
                print_with_timestamp('Please look at authorized_certs and '
                                     'search for obvious errors located at {}'.format(AUTHORIZED_CERTS_PATH))
                print_with_timestamp('Or delete the file altogether, '
                                     'but then you would have to pair your phone(s) again')
                return b''
    else:
        return b''


def add_to_authorized_certs(cert_der):
    sha1 = hashlib.sha1(cert_der).hexdigest().upper()
    sha1_format = [sha1[x:x + 2] for x in range(0, len(sha1), 2)]
    if not cert_der in parse_authorized_certs():
        with open(AUTHORIZED_CERTS_PATH, 'a+') as f:
            f.seek(0)
            lines = f.readlines()
            first_char_to_write = ''
            if lines:
                lastchar = lines[-1][-1]
                if lastchar != '\n':
                    first_char_to_write = '\n'

            f.write(''.join([first_char_to_write, ':'.join(sha1_format),
                             ' ', base64.b64encode(cert_der).decode(), '\n']))

        print_with_timestamp('Certificate with fingerprint: {} saved successfully'.format(' '.join(sha1_format)))
    else:
        print_with_timestamp('Certificate with fingerprint: {} is already in authorized_certs'.format(' '.join(sha1_format)))


def create_default_config_file_and_exit():
    config_parser = configparser.ConfigParser(allow_no_value=True)
    config_parser['tcp'] = {'tcp_server': 'on',
                            'tcp_port': '46352'}
    config_parser['bluetooth'] = {'bluetooth_server': 'off'}
    config_parser.add_section('notification')
    config_parser.set('notification', '# notification_timeout: display notification for this many seconds')
    config_parser.set('notification', '# set 0 to never expire')
    config_parser.set('notification', '# this setting might be completely ignored by your notification server')
    config_parser.set('notification', 'notification_timeout', '5')
    config_parser.set('notification', '\n# list_size_duplicates: number of latest notifications to keep')
    config_parser.set('notification', '# integer 0-50, if a notification is in this list it will not be shown')
    config_parser.set('notification', '# set to 0 to disable')
    config_parser.set('notification', 'list_size_duplicates', '2')
    config_parser.set('notification', '\n# ignore_duplicates_list_for_titles: notification titles that ignore duplicates list')
    config_parser.set('notification', '# comma-separated, case-sensitive')
    config_parser.set('notification', 'ignore_duplicates_list_for_titles', 'AN2Linux, title, Snapchat')
    with open(CONF_FILE_PATH, 'w') as configfile:
        config_parser.write(configfile)
    print_with_timestamp('Created new default configuration file at "{}"'.format(CONF_FILE_PATH))
    print_with_timestamp('Exiting... (why?) so you can look at and edit the configuration file, '
                         'after that run this program again')
    sys.exit()


def parse_config_or_create_new():
    if not os.path.isfile(CONF_FILE_PATH):
        create_default_config_file_and_exit()
    else:
        try:
            config_parser = configparser.ConfigParser(allow_no_value=True)
            config_parser.read(CONF_FILE_PATH)
            tcp_server_enabled = config_parser.getboolean('tcp', 'tcp_server')
            tcp_port_number = config_parser.getint('tcp', 'tcp_port')
            if tcp_port_number < 0 or tcp_port_number > 65535:
                print('Invalid port, port must be 0-65535')
                sys.exit(1)
            bluetooth_server_enabled = config_parser.getboolean('bluetooth', 'bluetooth_server')
            notification_timeout_milliseconds = config_parser.getint('notification', 'notification_timeout') * 1000
            if notification_timeout_milliseconds < 0:
                notification_timeout_milliseconds = 0
            list_size_duplicates = config_parser.getint('notification', 'list_size_duplicates')
            if list_size_duplicates < 0:
                list_size_duplicates = 0
            elif list_size_duplicates > 50:
                list_size_duplicates = 50
            Notification.latest_notifications = deque(maxlen=list_size_duplicates)
            ignore_duplicates_list_for_titles = config_parser.get('notification', 'ignore_duplicates_list_for_titles')
            Notification.titles_that_ignore_latest = [title.strip() for title in ignore_duplicates_list_for_titles.split(',')]
            return tcp_server_enabled, tcp_port_number, bluetooth_server_enabled, notification_timeout_milliseconds
        except (configparser.Error, ValueError) as e:
            print_with_timestamp('Corrupted configuration file: {}'.format(e))
            try:
                os.rename(CONF_FILE_PATH, CONF_FILE_PATH + ".corrupted")
                print_with_timestamp('Your corrupted configuration file has been saved to "{}"'
                                     .format(CONF_FILE_PATH + '.corrupted'))
            except Exception:
                pass
            create_default_config_file_and_exit()


def cleanup(signum, frame):
    if tcp_server_enabled:
        tcp_server.shutdown()
        if TCPHandler.active_pairing_connection:
            TCPHandler.cancel_pairing = True

    if bluetooth_server_enabled:
        bluetooth_server.shutdown()
        if BluetoothHandler.active_pairing_connection:
            BluetoothHandler.cancel_pairing = True

    shutil.rmtree(TMP_DIR_PATH, ignore_errors=True)

    main_loop.quit()
    sys.exit()


def init():
    if os.environ.get('XDG_CONFIG_HOME') is None or os.environ.get('XDG_CONFIG_HOME') == '':
        XDG_CONFIG_HOME = os.path.join(os.path.expanduser('~'), '.config')
    else:
        XDG_CONFIG_HOME = os.environ.get('XDG_CONFIG_HOME')

    CONF_DIR_PATH = os.path.join(XDG_CONFIG_HOME, 'an2linux')
    CONF_FILE_PATH = os.path.join(CONF_DIR_PATH, 'config')

    CERTIFICATE_PATH = os.path.join(CONF_DIR_PATH, 'certificate.pem')
    RSA_PRIVATE_KEY_PATH = os.path.join(CONF_DIR_PATH, 'rsakey.pem')
    AUTHORIZED_CERTS_PATH = os.path.join(CONF_DIR_PATH, 'authorized_certs')

    TMP_DIR_PATH = os.path.join(tempfile.gettempdir(), 'an2linux')

    if not os.path.exists(CONF_DIR_PATH):
        os.makedirs(CONF_DIR_PATH)

    if not os.path.exists(TMP_DIR_PATH):
        os.makedirs(TMP_DIR_PATH)

    if not os.path.isfile(CERTIFICATE_PATH) or not os.path.isfile(RSA_PRIVATE_KEY_PATH):
        generate_server_private_key_and_certificate(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)
    else:
        # test if valid private key / certificate
        try:
            ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2).load_cert_chain(CERTIFICATE_PATH,
                                                                          RSA_PRIVATE_KEY_PATH)
            ssl.PEM_cert_to_DER_cert(open(CERTIFICATE_PATH, 'r').read())
        except (ssl.SSLError, ValueError) as e:
            print_with_timestamp('Something went wrong trying to load your private key and certificate: {}'.format(e))
            print_with_timestamp('Will generate new key overwriting old key and certificate')
            generate_server_private_key_and_certificate(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)

    return CONF_FILE_PATH, CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH, AUTHORIZED_CERTS_PATH, TMP_DIR_PATH


if __name__ == '__main__':
    CONF_FILE_PATH, CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH, AUTHORIZED_CERTS_PATH, TMP_DIR_PATH = \
        init()

    tcp_server_enabled, tcp_port_number, bluetooth_server_enabled, notification_timeout_milliseconds = \
        parse_config_or_create_new()

    if not tcp_server_enabled and not bluetooth_server_enabled:
        print_with_timestamp('Neither TCP nor Bluetooth is enabled in your config file at {}'.format(CONF_FILE_PATH))
        sys.exit()

    SERVER_CERT_DER = ssl.PEM_cert_to_DER_cert(open(CERTIFICATE_PATH, 'r').read())
    sha1 = hashlib.sha1(SERVER_CERT_DER).hexdigest().upper()
    sha1_format = [sha1[x:x + 2] for x in range(0, len(sha1), 2)]
    print_with_timestamp('Server certificate fingerprint: {}'.format(' '.join(sha1_format)))

    PAIR_REQUEST = b'\x00'
    NOTIF_CONN = b'\x01'
    DENY_PAIRING = b'\x02'
    ACCEPT_PAIRING = b'\x03'
    FLAG_INCLUDE_TITLE = 1
    FLAG_INCLUDE_MESSAGE = 2
    FLAG_INCLUDE_ICON = 4

    notif_tls_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
    notif_tls_ctx.load_cert_chain(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)
    notif_tls_ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA')
    notif_tls_ctx.set_ecdh_curve('prime256v1')
    notif_tls_ctx.options |= ssl.OP_SINGLE_ECDH_USE
    notif_tls_ctx.verify_mode = ssl.CERT_REQUIRED

    if tcp_server_enabled:
        tcp_server = socketserver.ThreadingTCPServer(("", tcp_port_number), TCPHandler)
        print_with_timestamp('(TCP) Waiting for connections on port {}'.format(tcp_port_number))
        threading.Thread(target=tcp_server.serve_forever).start()

    if bluetooth_server_enabled:
        try:
            from bluetooth import *
            bluetooth_server = ThreadingBluetoothServer()
            print_with_timestamp('(Bluetooth) Waiting for connections on RFCOMM channel {}'
                                 .format(bluetooth_server.port))
            threading.Thread(target=bluetooth_server.serve_forever).start()
        except ImportError as e:
            bluetooth_server_enabled = False
            print_with_timestamp('Dependency missing: python-bluez')
            print(e)

    # so we can recieve callbacks from notifications being closed
    main_loop = GLib.MainLoop()
    threading.Thread(target=main_loop.run).start()

    signal.signal(signal.SIGHUP, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGQUIT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    signal.pause()

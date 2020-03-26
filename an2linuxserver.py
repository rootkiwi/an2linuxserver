#!/usr/bin/env python3
#
# Copyright 2017 rootkiwi
#
# AN2Linux-server is licensed under GNU General Public License 3, with the additional
# special exception to link portions of this program with the OpenSSL library.
#
# See LICENSE for more details.

import logging
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
try:
    gi.require_version('GdkPixbuf', '2.0')
    from gi.repository import GdkPixbuf
except (ImportError, ValueError) as e:
    print('Dependency missing: GdkPixbuf')
    print(e)
    sys.exit(1)
import threading
import datetime
import os
import configparser
import struct
import socketserver
import socket
import signal
import time
import subprocess
import hashlib
import termios
import base64
import select
import re
from collections import deque


class Notification:

    # this is a deque of the latest notifications hash to be able to skip duplicates
    latest_notifications = None

    # this is a list of notification titles that ignore the latest_notifications list
    titles_that_ignore_latest = None

    # list of keywords that trigger notifcation to be ignored
    keywords_to_ignore = None
    
    #regexes of title and contents of notifications to be ignored
    regexes_to_ignore_in_title = None
    regexes_to_ignore_in_content = None

    def __init__(self, title, message, icon_bytes=None):
        self.title = title
        self.message = message
        self.icon_bytes = icon_bytes
        self.notif_hash = hashlib.sha256(title.encode() + message.encode()
                                         + icon_bytes if icon_bytes is not None else b'').digest()

    def show(self):
        if (self.notif_hash not in Notification.latest_notifications
            or self.title in Notification.titles_that_ignore_latest) \
          and not any(kw in self.title for kw in Notification.keywords_to_ignore if kw != '') \
          and not any(regex.match(self.title) for regex in Notification.regexes_to_ignore_in_title) \
          and not any(regex.match(self.message) for regex in Notification.regexes_to_ignore_in_content):
            Notification.latest_notifications.append(self.notif_hash)
            self.notif = Notify.Notification.new(self.title, self.message, '')
            self.notif.set_timeout(notification_timeout_milliseconds)
            self.notif.set_hint('desktop-entry', GLib.Variant('s', 'an2linux'))
            if self.icon_bytes is not None:
                pixbuf_loader = GdkPixbuf.PixbufLoader.new()
                pixbuf_loader.write(self.icon_bytes)
                pixbuf_loader.close()
                self.notif.set_image_from_pixbuf(pixbuf_loader.get_pixbuf())
            try:
                self.notif.show()
            except Exception as e:
                logging.error('(Notification) Error showing notification:' \
                              ' {}'.format(e));
                logging.error('Please make sure you have a notification' \
                              ' server installed on your system')


class TCPHandler(socketserver.BaseRequestHandler):

    active_pairing_connection = False
    cancel_pairing = False

    def handle(self):
        try:
            conn_type = self.request.recv(1)
            if conn_type == PAIR_REQUEST and not TCPHandler.active_pairing_connection:
                TCPHandler.active_pairing_connection = True
                TCPHandler.cancel_pairing = False
                try:
                    self.handle_pair_request()
                except Exception as e:
                    logging.error('(TCP) Error pair_request: {}'.format(e))
                TCPHandler.active_pairing_connection = False
            elif conn_type == NOTIF_CONN:
                try:
                    self.handle_notification_connection()
                except Exception as e:
                    logging.error('(TCP) Error notif_conn: {}'.format(e))
        except Exception as e:
            logging.error('(TCP) Error handle: {}'.format(e))

    def handle_pair_request(self):
        pair_tls_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
        pair_tls_ctx.load_cert_chain(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)
        pair_tls_ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA')
        pair_tls_ctx.set_ecdh_curve('prime256v1')
        pair_tls_ctx.options |= ssl.OP_SINGLE_ECDH_USE

        try:
            tls_socket = pair_tls_ctx.wrap_socket(self.request, server_side=True)
        except ssl.SSLError as ssle:
            logging.error('(TCP) Failed TLS handshake pair_request: {}'.format(ssle))
            return

        ip = self.client_address[0]
        # remove first ::ffff: if ipv4 mapped ipv6 address
        if len(ip) > 7 and ip[:7] == '::ffff:':
            ip = ip[7:]
        logging.info('(TCP) Pair request from: {}\n'.format(ip))

        client_cert_size = struct.unpack('>I', recvall(tls_socket, 4))[0]
        client_cert = recvall(tls_socket, client_cert_size)

        sha256 = hashlib.sha256(client_cert + SERVER_CERT_DER).hexdigest().upper()
        sha256_format = [sha256[x:x + 2] for x in range(0, len(sha256), 2)]

        print('It is very important that you verify that the following hash matches what is viewed on your phone\n'
              'It is a sha256 hash like so: sha256(client_cert + server_cert)\n\n'
              'If the hash don\'t match there could be a man-in-the-middle attack\n'
              'Or something else is not right, you should abort if they don\'t match!\n')
        print(' '.join(sha256_format[:8]))
        print(' '.join(sha256_format[8:16]))
        print(' '.join(sha256_format[16:24]))
        print(' '.join(sha256_format[24:]))

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
            logging.error('(TCP) Failed TLS handshake notif_conn: {}'.format(e))
            return

        # one recv should not take longer than 10 sec
        tls_socket.settimeout(10)

        notification_flags = struct.unpack('>B', tls_socket.recv(1))[0]

        include_title   = chkflags(notification_flags, FLAG_INCLUDE_TITLE)
        include_message = chkflags(notification_flags, FLAG_INCLUDE_MESSAGE)
        include_icon    = chkflags(notification_flags, FLAG_INCLUDE_ICON)

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
            icon_size = struct.unpack('>I', recvall(tls_socket, 4))[0]
            icon_bytes = recvall(tls_socket, icon_size)
            try:
                Notification(title, message, icon_bytes).show()
            except Exception:
                Notification(title, message).show()
        else:
            Notification(title, message).show()


class ThreadingDualStackServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


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
                BluetoothHandler.active_pairing_connection = True
                BluetoothHandler.cancel_pairing = False
                try:
                    self.handle_pair_request()
                except Exception as e:
                    logging.error('(Bluetooth) Error pair_request: {}'.format(e))
                BluetoothHandler.active_pairing_connection = False
            elif conn_type == NOTIF_CONN:
                try:
                    self.handle_notification_connection()
                except Exception as e:
                    logging.error('(Bluetooth) Error notif_conn: {}'.format(e))
        except Exception as e:
            logging.error('(Bluetooth) Error handle: {}'.format(e))
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
        if bluetooth_support_kitkat:
            pair_tls_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1)
            pair_tls_ctx.set_ciphers('DHE-RSA-AES256-SHA')
            pair_tls_ctx.load_dh_params(DHPARAM_PATH)
        else:
            pair_tls_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
            pair_tls_ctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA')
            pair_tls_ctx.set_ecdh_curve('prime256v1')

        pair_tls_ctx.load_cert_chain(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)

        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls_bio = pair_tls_ctx.wrap_bio(incoming=self.incoming, outgoing=self.outgoing, server_side=True)

        try:
            self.do_handshake()
        except ssl.SSLError as ssle:
            logging.error('(Bluetooth) Failed TLS handshake pair_request: {}'.format(ssle))
            return

        logging.info('(Bluetooth) Pair request from: {}\n'.format(self.address))

        '''I don't know how else to do this when using SSLEngine/SSL_BIO, I don't see any security
        issue with sending the length of the encrypted data in cleartext, using something like wireshark
        it's possible to see the length anyway'''
        client_cert_size = struct.unpack('>I', recvall(self.socket, 4))[0]
        client_cert_encrypted = recvall(self.socket, client_cert_size)
        client_cert = self.tls_decrypt(client_cert_encrypted)

        sha256 = hashlib.sha256(client_cert + SERVER_CERT_DER).hexdigest().upper()
        sha256_format = [sha256[x:x + 2] for x in range(0, len(sha256), 2)]

        print('It is very important that you verify that the following hash matches what is viewed on your phone\n'
              'It is a sha256 hash like so: sha256(client_cert + server_cert)\n\n'
              'If the hash don\'t match there could be a man-in-the-middle attack\n'
              'Or something else is not right, you should abort if they don\'t match!\n')
        print(' '.join(sha256_format[:8]))
        print(' '.join(sha256_format[8:16]))
        print(' '.join(sha256_format[16:24]))
        print(' '.join(sha256_format[24:]))

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
            if bluetooth_support_kitkat:
                notif_tls_ctx_kitkat_bt.load_verify_locations(cadata=parse_authorized_certs())
                self.tls_bio = notif_tls_ctx_kitkat_bt.wrap_bio(incoming=self.incoming, outgoing=self.outgoing,
                                                                server_side=True)
            else:
                notif_tls_ctx.load_verify_locations(cadata=parse_authorized_certs())
                self.tls_bio = notif_tls_ctx.wrap_bio(incoming=self.incoming, outgoing=self.outgoing, server_side=True)
            self.do_handshake()
        except Exception as e:
            logging.error('(Bluetooth) Failed TLS handshake notif_conn: {}'.format(e))
            return

        # one recv should not take longer than 10 sec
        self.socket.settimeout(10)

        notification_flags_size = struct.unpack('>I', recvall(self.socket, 4))[0]
        notification_flags_encrypted = recvall(self.socket, notification_flags_size)
        notification_flags = struct.unpack('>B', self.tls_decrypt(notification_flags_encrypted))[0]

        include_title   = chkflags(notification_flags, FLAG_INCLUDE_TITLE)
        include_message = chkflags(notification_flags, FLAG_INCLUDE_MESSAGE)
        include_icon    = chkflags(notification_flags, FLAG_INCLUDE_ICON)

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
            icon_size = struct.unpack('>I', recvall(self.socket, 4))[0]
            icon_encrypted = recvall(self.socket, icon_size)
            icon_bytes = self.tls_decrypt(icon_encrypted)
            try:
                Notification(title, message, icon_bytes).show()
            except Exception:
                Notification(title, message).show()
        else:
            Notification(title, message).show()


def chkflags(flags, flag):
    return flags & flag == flag


def recvall(sock, size):
    buf = bytearray()
    while len(buf) < size:
        tmp = sock.recv(size - len(buf))
        if tmp == b'':
            raise ConnectionResetError('connection reset by peer')
        buf.extend(tmp)
    return buf


def generate_dhparam():
    logging.info('Since you have enabled bluetooth support for android 4.4 kitkat I will now need to')
    logging.info('Generate DH parameters, which is going to take a while')
    logging.info('On my laptop (Intel i5) it took ~16 minutes')
    dhparam_process = subprocess.Popen(['openssl', 'dhparam', '-out', DHPARAM_PATH, '4096'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stderr = dhparam_process.communicate()[1]
    if dhparam_process.returncode == 0:
        logging.info('Generated DH parameters 4096 bit')
        logging.info('Saved to: ' + DHPARAM_PATH)
    else:
        logging.error('Error generating DH parameters, exiting..')
        logging.error(stderr)
        sys.exit(1)


def generate_server_private_key_and_certificate(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH):
    openssl_process = subprocess.Popen(['openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-nodes', '-sha256',
                                        '-keyout', RSA_PRIVATE_KEY_PATH, '-out', CERTIFICATE_PATH,
                                        '-days', '3650', '-subj', '/CN=an2linuxserver'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stderr = openssl_process.communicate()[1]
    if openssl_process.returncode == 0:
        logging.info('Generated a 4096 bit RSA private key')
        logging.info('Key saved to: ' + RSA_PRIVATE_KEY_PATH)
        logging.info('Certificate saved to: ' + CERTIFICATE_PATH)
    else:
        logging.error('Error generating private key, exiting..')
        logging.error(stderr)
        sys.exit(1)


def parse_authorized_certs():
    if os.path.isfile(AUTHORIZED_CERTS_PATH):
        with open(AUTHORIZED_CERTS_PATH, 'r') as f:
            try:
                authorized_certs = b''.join([base64.b64decode(line.split(' ')[1])
                                 for line in f.readlines() if len(line.split(' ')) == 2])
                # testing if valid certificates
                ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2).load_verify_locations(cadata=authorized_certs)
                return authorized_certs
            except Exception as e:
                logging.error('Corrupted authorized_certs file: {}'.format(e))
                logging.error('Please look at authorized_certs and '
                              'search for obvious errors located at {}'.format(AUTHORIZED_CERTS_PATH))
                logging.error('Or delete the file altogether, '
                              'but then you would have to pair your phone(s) again')
                return b''
    else:
        return b''


def add_to_authorized_certs(cert_der):
    sha256 = hashlib.sha256(cert_der).hexdigest().upper()
    sha256_format = [sha256[x:x + 2] for x in range(0, len(sha256), 2)]
    if not cert_der in parse_authorized_certs():
        with open(AUTHORIZED_CERTS_PATH, 'a+') as f:
            f.seek(0)
            lines = f.readlines()
            first_char_to_write = ''
            if lines:
                lastchar = lines[-1][-1]
                if lastchar != '\n':
                    first_char_to_write = '\n'

            f.write(''.join([first_char_to_write, 'SHA256:', ':'.join(sha256_format),
                             ' ', base64.b64encode(cert_der).decode(), '\n']))

        logging.info('Certificate with fingerprint: {} saved successfully'.format(' '.join(sha256_format)))
    else:
        logging.info('Certificate with fingerprint: {} is already in authorized_certs'.format(' '.join(sha256_format)))


def create_default_config_file_and_exit():
    config_parser = configparser.ConfigParser(allow_no_value=True)
    config_parser['tcp'] = {'tcp_server': 'on',
                            'tcp_port': '46352'}
    config_parser.add_section('bluetooth')
    config_parser.set('bluetooth', 'bluetooth_server', 'off')
    config_parser.set('bluetooth', '\n# bluetooth_support_kitkat: enable bluetooth support for android 4.4 kitkat')
    config_parser.set('bluetooth', '# this setting is important for everyone using bluetooth')
    config_parser.set('bluetooth', '# you need to set this setting correctly otherwise it will not work')
    config_parser.set('bluetooth', '# if you are using android 4.4 kitkat this needs to be turned on')
    config_parser.set('bluetooth', '# because some cipher versions are not supported until after kitkat')
    config_parser.set('bluetooth', '# if you are using android 5.0+ you need to keep this setting off')
    config_parser.set('bluetooth', 'bluetooth_support_kitkat', 'off')
    config_parser.add_section('notification')
    config_parser.set('notification', '# notification_timeout: display notification for this many seconds')
    config_parser.set('notification', '# set 0 to never expire')
    config_parser.set('notification', '# this setting might be completely ignored by your notification server')
    config_parser.set('notification', 'notification_timeout', '5')
    config_parser.set('notification', '\n# list_size_duplicates: number of latest notifications to keep')
    config_parser.set('notification', '# integer 0-50, if a notification is in this list it will not be shown')
    config_parser.set('notification', '# set to 0 to disable')
    config_parser.set('notification', 'list_size_duplicates', '0')
    config_parser.set('notification', '\n# ignore_duplicates_list_for_titles: notification titles that ignore duplicates list')
    config_parser.set('notification', '# comma-separated, case-sensitive')
    config_parser.set('notification', 'ignore_duplicates_list_for_titles', 'AN2Linux, title')
    config_parser.set('notification', '\n# keywords_to_ignore: do not show notifications that include these keywords in the notification titles')
    config_parser.set('notification', '# comma-separated, case-sensitive. leading and trailing whitespace will be stripped.')
    config_parser.set('notification', 'keywords_to_ignore', '')
    config_parser.set('notification', '\n# regexes_to_ignore: do not show notifications who\'s contents or title match the following regexes')
    config_parser.set('notification', 'regexes_to_ignore_in_title', '')
    config_parser.set('notification', 'regexes_to_ignore_in_content', '')
    with open(CONF_FILE_PATH, 'w') as configfile:
        config_parser.write(configfile)
    logging.info('Created new default configuration file at "{}"'.format(CONF_FILE_PATH))
    logging.info('Exiting... (why?) so you can look at and edit the configuration file, '
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
                logging.error('Invalid port, port must be 0-65535')
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

            keywords_to_ignore = config_parser.get('notification', 'keywords_to_ignore')
            Notification.keywords_to_ignore = [kw.strip() for kw in keywords_to_ignore.split(',')]
            
            regexes_to_ignore_in_title = config_parser.get('notification', 'regexes_to_ignore_in_title')
            Notification.regexes_to_ignore_in_title = [re.compile(kw.strip()) for kw in regexes_to_ignore_in_title.split(',')] if regexes_to_ignore_in_title else []

            regexes_to_ignore_in_content = config_parser.get('notification', 'regexes_to_ignore_in_content')
            Notification.regexes_to_ignore_in_content = [re.compile(kw.strip()) for kw in regexes_to_ignore_in_content.split(',')] if regexes_to_ignore_in_content else []


            try:
                bluetooth_support_kitkat = config_parser.getboolean('bluetooth', 'bluetooth_support_kitkat')
            except (configparser.Error, ValueError):
                bluetooth_support_kitkat = False
                logging.info('Cound not find setting "bluetooth_support_kitkat" in your config file')
                logging.info('This is a new setting that has been added')
                logging.info('For now I will keep an2linux running and set this setting to off')
                logging.info('If you do not wan\'t to see these messages or you want to enable this setting')
                logging.info('Then turn off an2linux and rename or delete your current config file')
                logging.info('Located at: "{}"'.format(CONF_FILE_PATH))
                logging.info('Then start an2linux again to generate a new config file including this setting')
            return tcp_server_enabled, tcp_port_number,\
                   bluetooth_server_enabled, bluetooth_support_kitkat, notification_timeout_milliseconds
        except (configparser.Error, ValueError) as e:
            logging.error('Corrupted configuration file: {}'.format(e))
            try:
                os.rename(CONF_FILE_PATH, CONF_FILE_PATH + ".corrupted")
                logging.error('Your corrupted configuration file has been saved to "{}"'
                                     .format(CONF_FILE_PATH + '.corrupted'))
            except Exception:
                pass
            create_default_config_file_and_exit()


def cleanup(signum, frame):
    Notify.uninit()
    if tcp_server_enabled:
        tcp_server.shutdown()
        if TCPHandler.active_pairing_connection:
            TCPHandler.cancel_pairing = True

    if bluetooth_server_enabled:
        bluetooth_server.shutdown()
        if BluetoothHandler.active_pairing_connection:
            BluetoothHandler.cancel_pairing = True

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
    DHPARAM_PATH = os.path.join(CONF_DIR_PATH, 'dhparam.pem')

    if not os.path.exists(CONF_DIR_PATH):
        os.makedirs(CONF_DIR_PATH)

    if not os.path.isfile(CERTIFICATE_PATH) or not os.path.isfile(RSA_PRIVATE_KEY_PATH):
        generate_server_private_key_and_certificate(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)
    else:
        # test if valid private key / certificate
        try:
            ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2).load_cert_chain(CERTIFICATE_PATH,
                                                                          RSA_PRIVATE_KEY_PATH)
            ssl.PEM_cert_to_DER_cert(open(CERTIFICATE_PATH, 'r').read())
        except (ssl.SSLError, ValueError) as e:
            logging.error('Something went wrong trying to load your private key and certificate: {}'.format(e))
            logging.error('Will generate new key overwriting old key and certificate')
            generate_server_private_key_and_certificate(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)

    return CONF_FILE_PATH, CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH, AUTHORIZED_CERTS_PATH, DHPARAM_PATH


def configure_logging():
    log_folder =  os.path.join(os.environ.get('XDG_CACHE_HOME', os.path.expanduser('~/.cache')), 'an2linux')
    if not os.path.exists(log_folder):
        os.makedirs(log_folder, exist_ok=True)
    log_filename = 'an2linux_{0}.log'.format(datetime.datetime.now().strftime('%Y%m%d_%Hh%Mm%Ss'))
    log_filepath = os.path.join(log_folder, log_filename)

    # an2linux currently prints to stdout - we will keep this behaviour for now
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s.%(msecs).03d %(name)-12s %(levelname)-8s %(message)s (%(filename)s:%(lineno)d)',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_filepath),
            logging.StreamHandler(sys.stdout),
        ]
    )


if __name__ == '__main__':
    configure_logging()

    CONF_FILE_PATH, CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH, AUTHORIZED_CERTS_PATH, DHPARAM_PATH = init()

    tcp_server_enabled, tcp_port_number, bluetooth_server_enabled, bluetooth_support_kitkat,\
        notification_timeout_milliseconds = parse_config_or_create_new()

    if not tcp_server_enabled and not bluetooth_server_enabled:
        logging.error('Neither TCP nor Bluetooth is enabled in your config file at {}'.format(CONF_FILE_PATH))
        sys.exit()

    # initialize libnotify
    Notify.init('AN2Linux')

    SERVER_CERT_DER = ssl.PEM_cert_to_DER_cert(open(CERTIFICATE_PATH, 'r').read())
    sha256 = hashlib.sha256(SERVER_CERT_DER).hexdigest().upper()
    sha256_format = [sha256[x:x + 2] for x in range(0, len(sha256), 2)]
    logging.info('Server certificate fingerprint: {}'.format(' '.join(sha256_format)))

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
        try:
            # test if ipv4/ipv6 dual stacking is supported, otherwise use ipv4
            tcp_server = ThreadingDualStackServer(('', tcp_port_number), TCPHandler)
        except Exception:
            logging.error('(TCP) Failed to use IPv4/IPv6 dual stacking, fallbacks to IPv4 only')
            tcp_server = socketserver.ThreadingTCPServer(('', tcp_port_number), TCPHandler)
        logging.info('(TCP) Waiting for connections on port {}'.format(tcp_port_number))
        threading.Thread(target=tcp_server.serve_forever).start()

    if bluetooth_server_enabled:
        try:
            from bluetooth import *
            if bluetooth_support_kitkat:
                if not os.path.isfile(DHPARAM_PATH):
                    generate_dhparam()
                else:
                    try:
                        # try if valid dh parameters
                        ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2).load_dh_params(DHPARAM_PATH)
                    except Exception as e:
                        logging.error('Something went wrong trying to load your DH parameters: {}'.format(e))
                        logging.error('Will generate new parameters overwriting old parameters')
                        generate_dhparam()
                notif_tls_ctx_kitkat_bt = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1)
                notif_tls_ctx_kitkat_bt.load_cert_chain(CERTIFICATE_PATH, RSA_PRIVATE_KEY_PATH)
                notif_tls_ctx_kitkat_bt.set_ciphers('DHE-RSA-AES256-SHA')
                notif_tls_ctx_kitkat_bt.load_dh_params(DHPARAM_PATH)
                notif_tls_ctx_kitkat_bt.options |= ssl.OP_SINGLE_DH_USE
                notif_tls_ctx_kitkat_bt.verify_mode = ssl.CERT_REQUIRED

            bluetooth_server = ThreadingBluetoothServer()
            logging.info('(Bluetooth) Waiting for connections on RFCOMM channel {}'
                                 .format(bluetooth_server.port))
            threading.Thread(target=bluetooth_server.serve_forever).start()
        except ImportError as e:
            bluetooth_server_enabled = False
            logging.error('Dependency missing: python-bluez')

    signal.signal(signal.SIGHUP, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGQUIT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    signal.pause()

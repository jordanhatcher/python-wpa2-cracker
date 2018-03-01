# Python WPA2 Cracker

This is a simple script that attempts to find a password to a wireless network
using WPA2. It watches packets related to a specific wireless network and
captures a [4-way](https://en.wikipedia.org/wiki/IEEE_802.11i-2004) handshake
when a device connects to that network.

_Please don't try to use this for actually trying to break into wireless
networks. Not only is that illegal in most places, but this script is not
even remotely optimized compared to other freely available software tools.
This is only for leaning purposes only._

I also wrote a blog post about this project [on my website]() that you can
check out!

## Prerequisites
To run this script, you need the following:

- a computer running linux
- A wireless card/device capable of being used in monitoring mode
- Python 3

## Running
Clone the repo first `git clone https://github.com/jordanhatcher/python-wpa2-cracker`

Change into the project directory and edit the wpa2-cracker.py file.
The `WIFI_INTERFACE` variable needs to be updated to match the interface of
your wireless adapter.
The `SSID` variable needs to be updated to match the SSID of the network you
want to run the script against.
You may want to change how `PASSWORD_LIST` is generated. By default, it only
tries all passwords that are 8 hexadecimal digits long.

Run the script `sudo python3 wpa2-cracker.py`

The script will now do the following:
1. Capture a beacon frame containing the SSID to get the MAC address of the
access point.
2. Waits until a device connects to the network, then captures the generated
4-way handshake.
3. Tries to (*very slowly*) brute force the password for the wireless network.

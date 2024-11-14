import os

import pyshark

print()
print("Capturing")
print()
wifi_interface = "wlp5s0f4u2"
capture = pyshark.LiveCapture(interface=wifi_interface)


def print_info(packet):
    try:
        if not packet["WLAN.MGT"]:
            return
        if not packet["WLAN"]:
            return
        if not packet["WLAN_RADIO"]:
            return
        if packet["WLAN"].fc_type_subtype == "0x0004":
            if packet["WLAN"].ta:
                # print(packet)
                # print(packet["WLAN"])
                # print(packet["WLAN"].field_names)

                print()

                print("SignalS:", packet["WLAN_RADIO"].signal_dbm)

                print("SSID:", packet["WLAN.MGT"].wlan_ssid)
                # print(packet["WLAN"].fc_type_subtype)

                print("Source:", packet["WLAN"].ta)
                print("Freq:", packet["WLAN_RADIO"].frequency)
                print()
    except:
        pass


# capture.sniff_continuously(packet_count=

# capture.sniff(packet_count=3)
channel = 14

out_str = f'airmon-ng start "{wifi_interface}" {channel} >/dev/null 2>&1'
os.system("echo %s|sudo -S %s" % ("@hoothoot", out_str))
capture.apply_on_packets(print_info, packet_count=100)
channel = 1
iterations = 0
"""
while iterations < 100:
    if channel > 14:
        channel = 1
    out_str = f'airmon-ng start "{wifi_interface}" {channel} >/dev/null 2>&1'
    # print(out_str)
    os.system("echo %s|sudo -S %s" % ("@hoothoot", out_str))
    try:
        capture.apply_on_packets(print_info, packet_count=10)
    except Exception as ex:
        if type(ex) != TimeoutError:
            break
    channel += 1
"""

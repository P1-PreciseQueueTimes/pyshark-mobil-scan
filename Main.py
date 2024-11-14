import os

import pyshark

print()
print("Capturing")
print()
wifi_interface = "wlp5s0f4u2"
capture = pyshark.LiveCapture(interface=wifi_interface)


def print_info(packet):
    if packet["WLAN"] and packet["WLAN_RADIO"]:

        if packet["WLAN"].fc_type_subtype == "0x0004":
            if packet["WLAN"].ta:
                # print(packet["WLAN"])
                # print(packet["WLAN"].field_names)
                print()

                # print(packet["WLAN"].fc_type_subtype)

                print("Source:", packet["WLAN"].ta)
                if packet["WLAN"].ta == "a8:ba:69:04:9C:92":
                    print("Sui")

                print("Freq:", packet["WLAN_RADIO"].frequency)
                print()


# capture.sniff_continuously(packet_count=

# capture.sniff(packet_count=3)

channel = 1
iterations = 0
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

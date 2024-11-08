import xml.etree.ElementTree as Et

import pyshark

print()
print("Capturing")
print()
capture = pyshark.LiveCapture(interface="wlp5s0f4u2")


def print_info(packet):
    if packet["WLAN"]:
        if packet["WLAN"].fc_type_subtype == "0x0004":
            if packet["WLAN"].ta:
                # print(packet["WLAN"])
                # print(packet["WLAN"].field_names)
                # print()

                # print(packet["WLAN"].fc_type_subtype)
                print(packet["WLAN"].ta)


# capture.sniff_continuously(packet_count=3)

# capture.sniff(packet_count=3)

capture.apply_on_packets(print_info)

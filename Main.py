import os
import time

import pyshark


print("\nCapturing\n")

wifi_interface = "wlp5s0f4u2"
old_source = ""
old_time = time.time()
pi_source = "dc:a6:32:54:ac:c5"
capture = pyshark.LiveCapture(interface=wifi_interface)


def print_info(packet):
    global old_source, old_time
    try:
        if not packet["WLAN.MGT"] or not packet["WLAN"] or not packet["WLAN_RADIO"]:
            return

        if packet["WLAN"].fc_type_subtype == "0x0004" and packet["WLAN"].ta:
            if old_source == packet["WLAN"].ta:
                return
            if packet["WLAN"].ta == pi_source:
                current_time = time.time()
                now_time = current_time - old_time
                print("Pi")
                print(now_time)
                print()
                old_time = current_time
            old_source = packet["WLAN"].ta
    except Exception as e:
        print(f"Error processing packet: {e}")
        """
        print()
        print("SignalS:", packet["WLAN_RADIO"].signal_dbm)
        print("SSID:", packet["WLAN.MGT"].wlan_ssid)
        print("Source:", packet["WLAN"].ta)
        print("Freq:", packet["WLAN_RADIO"].frequency)
        print()
        """

channel = 13

out_str = f'airmon-ng start "{wifi_interface}" {channel} >/dev/null 2>&1'
os.system("echo %s|sudo -S %s" % ("@hoothoot", out_str))
capture.apply_on_packets(print_info, packet_count=100)
channel = 1
iterations = 0

# Hvis man vil sniffe efter flere kanaler
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

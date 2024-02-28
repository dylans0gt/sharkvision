import pyshark
import pyfiglet
import time


banner = pyfiglet.figlet_format("SharkVision", font="alligator")
print(banner)


def filter_packets(interface):
    capture = pyshark.LiveCapture(interface=interface)
    print("Capturing packets on interface {}...".format(interface))

    camera_detected = False

    # Set a start time
    start_time = time.time()

    # Set the duration to 1 minute and 45 seconds
    duration = 105

    while (time.time() - start_time) < duration:
        for packet in capture.sniff_continuously(timeout=1):
            if 'wlan_mgt' in packet and 'wlan' in packet:
                if hasattr(packet.wlan, 'tagged_parameters') and hasattr(packet.wlan_mgt, 'tagged_parameters'):
                    if packet.wlan_mgt.tagged_parameters:
                        for param in packet.wlan_mgt.tagged_parameters.split():
                            if param.startswith('OUI:') and param.split(':')[1].upper() in camera_OUIs:
                                print("ALERT: Potential camera detected!")
                                print(f"Name: {camera_OUIs[param.split(':')[1].upper()]}")
                                print(f"OUI: {param.split(':')[1]}")
                                print("Check your surroundings.")
                                print()
                                camera_detected = True

        if camera_detected:
            break

        remaining_time = duration - (time.time() - start_time)
        if remaining_time <= 0:
            break

        print(f"Time left: {int(remaining_time)} seconds")
        time.sleep(1)

    if not camera_detected:
        print("No cameras found, you're safe :p")


def main():
    global camera_OUIs
    camera_OUIs = {
        "ACCC8E": "Axis Communications AB",
        "002128": "Cisco",
        "001C73": "Arista Networks",
        "001987": "Panasonic Mobile Communications Co.,Ltd.",
        "000463": "Bosch Security Systems",
        "000131": "Bosch Security Systems, Inc.",
        "1868CB": "Hangzhou Hikvision Digital Technology Co.,Ltd.",
        "1012FB": "Hangzhou Hikvision Digital Technology Co.,Ltd.",
        "0002D1": "Vivotek",
        "48EA63": "Uniview",
        "001C27": "Wbox",
        "001C27": "Sunell",
        "00047D": "Pelco",
        "0003C5": "Mobotix",
        "0010BE": "March Networks I",
        "001281": "March Networks II",
        "000A13": "Honeywell",
        "0013E2": "Geovision",
        "001A07": "Arecont",
        "E43022": "Samsung Techwin I",
        "000918": "Samsung Techwin II",
        "00407F": "FLIR I",
        "001BD8": "FLIR II",
        "14A78B": "Dahua I",
        "38AF29": "Dahua II",
        "3CEF8C": "Dahua III",
        "4C11BF": "Dahua IV",
        "9002A9": "Dahua V",
        "BC325F": "Dahua VI",
        "E0508B": "Dahua VII",
        "AC9B0A": "Sony I",
        "AC9B0A": "Sony II",
        "00014A": "Sony III"
    }

    interface = 'en0'  # captures on en0 - wifi
    filter_packets(interface)


if __name__ == "__main__":
    main()

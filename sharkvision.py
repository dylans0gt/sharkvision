import pyshark
import pyfiglet


banner = pyfiglet.figlet_format("SharkVision", font = "alligator" ) 
print(banner) 

def filter_packets(interface):
    capture = pyshark.LiveCapture(interface=interface)
    print("Capturing packets on interface {}...".format(interface))

    camera_detected = False  # Flag to track if any potential camera is detected

    for packet in capture.sniff_continuously():
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

    if not camera_detected:  # If no cameras detected, print the message
        print("No cameras found, you're safe :p")

def main():
    global camera_OUIs
    camera_OUIs = {
        "ACCC8E": "Axis Communications AB",
        "002128": "Cisco",
        "001C73": "Arista Networks",
        # Add more camera OUIs here
    }

    interface = 'en0'  # Capture only on interface en0
    filter_packets(interface)

if __name__ == "__main__":
    main()


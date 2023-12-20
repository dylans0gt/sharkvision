import subprocess
import re
from pyfiglet import Figlet

big_banner = Figlet(font='cricket')
small_text = Figlet(font='term')
print(big_banner.renderText('SharkVision'))
print(small_text.renderText('Detect and track down hidden cameras in your vicinity...'))

def scan_network_for_ouis(ouis):

    # begin capturing traffic using tshark
    tshark_cmd = ['tshark', '-I', '-l', '-f', 'ether', '-Y', 'eth.addr']

    # capture output
    process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    # iterate throughout output
    for line in process.stdout:
        # extract MAC address from each line of output
        match = re.search(r'((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})', line)
        if match:
            mac_address = match.group(1)
            
            # check if address matches any specified common OUIs
            for oui in ouis:
                if mac_address.startswith(oui):
                    print(f"Found camera with OUI {oui}: {mac_address}.\It is recommended you walk around the area with a flashlight and see what surface bounces off the light. That will most likely be the hidden camera.")
    else:
        print("No spy cameras found. You are safe.")
        print(" ")

    process.terminate()

if __name__ == "__main__":
    # List of OUIs to search for
    # Arlo - A4:11:62
    # Avigilon: 00:18:85
    # Axis: 00:40:8C, AC:CC:8E
    # Bosch: 00:01:31, 00:04:63, 00:10:17, 00:1B:86, 00:1C:44, 00:07:5F
    # Dahua: 4C:11:BF, 90:02:A9
    # Hanwha: 00:09:18
    # Hikvision: 44:19:B6, C0:56:E3
    #Sony: 00:01:4A, 00:13:A9, 00:1A:80, 00:1D:BA, 00:24:BE, 08:00:46, 30:F9:ED, 3C:07:71, 54:42:49, 54:53:ED, 78:84:3C, D8:D4:3C, F0:BF:97, FC:F1:52
    
    target_ouis = [
        '00:18:85', '00:40:8C', 'AC:CC:8E', '00:01:31', '00:04:63',
        '00:10:17', '00:1B:86', '00:1C:44', '00:07:5F', '4C:11:BF',
        '90:02:A9', '00:09:18', '44:19:B6', 'C0:56:E3', '00:01:4A',
        '00:13:A9', '00:1A:80', '00:1D:BA', '00:24:BE', '08:00:46',
        '30:F9:ED', '3C:07:71', '54:42:49', '54:53:ED', '78:84:3C',
        'D8:D4:3C', 'F0:BF:97', 'FC:F1:52', 'A4:11:62'
    ]

    # execute function
    scan_network_for_ouis(target_ouis)


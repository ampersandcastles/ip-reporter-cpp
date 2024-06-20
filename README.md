# IP Reporter (I copied this from my python project)

IP Reporter is a ~Python~ C++-based tool for network administrators to monitor and capture IP and MAC addresses of network devices. It provides a simple graphical user interface (GUI) to display and export the captured data. The tool is useful for managing network devices, especially in environments like mining farms where multiple devices need to be tracked. Currently this only works on Antminer machines as it's what I have access to.

## Features

- **Network Packet Sniffing**: Captures network packets to extract IP and MAC addresses.
- **Graphical User Interface**: Provides a clean and simple GUI using Tkinter.
- **Start/Stop Functionality**: Easily start or stop packet sniffing with a button click.
- **Data Export**: Export captured data to a text file.
- **Click to Open**: Double-click on an IP address to open it in the default web browser with pre-filled login credentials.

## Dependencies

- Python 3.x
- Scapy
- Tkinter (comes with standard Python installations)
- Webbrowser (comes with standard Python installations)

### Installation

1. **Python 3.x**: Ensure you have Python 3.x installed on your system. You can download it from [python.org](https://www.python.org/).

2. **Scapy**: Install Scapy using pip.

   ```sh
   pip install scapy
   ```

3. **Set Capabilities** (Optional): If you want to run the script without root privileges, set capabilities on your Python interpreter.
   ```sh
   sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
   ```

## Usage

1. **Clone the Repository**:

   ```sh
   git clone https://github.com/ampersandcastles/ip-reporter.git
   cd ip-reporter
   ```

2. **Run the Script**:

   ```sh
   python3 reporter.py

   ```

   or

   ```sh
   python3 gui.py

   ```

3. **GUI Interface**:
   - Click "Start" to begin packet sniffing.
   - Captured IP and MAC addresses will be displayed in the table.
   - Double-click on an IP address to open it in your default web browser.
   - Click "Export" to save the captured data to a text file.

## Code Overview

- `reporter.py`: Main script containing the GUI and packet sniffing functionality.

### Packet Sniffing

The script uses Scapy to sniff network packets and extract the IP and MAC addresses of devices.

### CLI version

Works very similarly to GUI version, just command line. All properties still apply minus the autologin.

### Graphical User Interface

The GUI is built using Tkinter, providing a table to display captured data, and buttons to start/stop sniffing and export data.

### Open in Browser

Double-clicking on an IP address in the table opens it in the default web browser with the login credentials (`root/root`) pre-filled in the URL.

## Security Note

While the tool attempts to simplify device management by allowing auto-login to devices via URLs with embedded credentials, this method is generally insecure and should be used with caution. It's recommended to use more secure methods of authentication and avoid embedding credentials in URLs where possible.

## Contributing

Feel free to contribute to this project by submitting issues or pull requests. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The developers and maintainers of [Scapy](https://scapy.net/).
- The Python community for providing excellent libraries and support.
- Honestly, ChatGPT.

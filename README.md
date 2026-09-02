# TP-Link extender communicator

Talk with a TP-Link extender over SSH.

## Demo
1. Install the requirements from requirements.txt with pip or [uv](https://docs.astral.sh/uv/#installation) or whatever you prefer
2. Run sshclient.py and supply the IP and password (same as the one for the web panel or Tether app) for your extender and receive simple information about your extender in return

## Usage
```py
from sshclient import TPClient, OpCodes
# create the client
client = TPClient(hostname="your extender's ip here", password="password here")

# get some information (like the time) from the device
response = client.send(OpCodes.TMP_APPV1_OP_SYSTEM_TIME_V1_GET)
print(response.data)

# make the device do something more interesting (toggle the leds)
msg = client.send(OpCodes.TMP_APPV1_OP_LED_GET)
original_led_status = msg.data["enable"]
print("Current LED status:", original_led_status)
msg = client.send(OpCodes.TMP_APPV1_OP_LED_SET, {"enable": not original_led_status})
msg = client.send(OpCodes.TMP_APPV1_OP_LED_GET)
print("Current LED status:", msg.data["enable"])
```

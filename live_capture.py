import asyncio
import pyshark


try:
    asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

print("Starting live capture on Wi-Fi interface...")

capture = pyshark.LiveCapture(interface="Wi-Fi")

packet_limit = 10  # minimum limit of the packet to capture 
count = 0

for packet in capture.sniff_continuously():  
    count += 1
    print(f"{count}. Highest Layer: {packet.highest_layer}, Length: {packet.length}")
    
    if count >= packet_limit:
        print("\nCapture complete.")
        break

capture.close()  #Gracefully termination ke liye , tshark terminate and resuoure free 

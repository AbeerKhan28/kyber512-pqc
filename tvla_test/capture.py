import serial

port = "COM5"  # Adjust to your COM port
baud = 115200

print(f"Connecting to {port}...")
ser = serial.Serial(port, baud, timeout=2)

with open("trace.csv", "w") as f:
    while True:
        raw_line = ser.readline().decode("utf-8", errors="ignore")
        if not raw_line:
            continue
        print(raw_line, end="")
        f.write(raw_line)
        if "TVLA collection complete" in raw_line:
            break

ser.close()
print("Capture complete! Output saved to trace.csv")

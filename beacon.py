import socket
import time


TARGET = "1.1.1.1"

PORT = 4444


while True:

    try:

        s = socket.socket()

        s.connect((TARGET, PORT))

        s.send(b"hello")

        s.close()

        print("Beacon sent")

    except Exception as e:

        print(e)

    time.sleep(10)
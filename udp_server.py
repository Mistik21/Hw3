import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 9999))

print("UDP server listening on 9999")

while True:
    data, address = sock.recvfrom(1024)
    sock.sendto(b"Hello", address)
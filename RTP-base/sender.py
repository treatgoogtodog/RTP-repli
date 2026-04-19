import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472
MAX_DATA_CHUNK = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5

def build_byte(type, seq_num, data) -> bytes:
    """Build byte for a packet"""
    pkt_header = PacketHeader(type=type, seq_num=seq_num, length=len(data))
    pkt_header.checksum = 0
    checksum = compute_checksum(pkt_header / data)
    pkt_header.checksum = checksum
    return bytes(pkt_header / data)

def read_input() -> list[tuple[int, bytes]]:
    """Read input from sys.stdin and split into chunks of size MAX_DATA_CHUNK."""
    data = sys.stdin.buffer.read()
    chunks = [data[i:i + MAX_DATA_CHUNK] for i in range(0, len(data), MAX_DATA_CHUNK)]
    sequence_numbers = list(range(1, len(chunks) + 1))
    return list(zip(sequence_numbers, chunks))

def socket_setup() -> tuple[socket.socket, tuple[str, int]]:
    """Set up a UDP socket and bind it to sender IP and port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    peer = socket.getpeername()
    s.bind(peer)
    return s, peer

def init_handshake(s: socket.socket, peer: tuple[str, int], window_size: int) -> None:
    """Perform handshake with receiver to establish connection and exchange window size."""
    start = build_byte(type=0, seq_num=0, data=str(window_size).encode())
    s.sendto(start, peer)
    while True:
        try:
            data, _ = s.recvfrom(MAX_PACKET_SIZE)
            pkt = PacketHeader(data)
            check_integrity = compute_checksum(PacketHeader(type=pkt.type, seq_num=pkt.seq_num, length=pkt.length, checksum=0) / data[16:]) == pkt.checksum
            if pkt.type == 1 and pkt.seq_num == 0 and check_integrity:
                break
        except socket.timeout:
            s.sendto(start, peer)
    


def sender(receiver_ip, receiver_port, window_size) -> None:
    """TODO: Open socket and send message from sys.stdin."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pkt_header = PacketHeader(type=2, seq_num=10, length=14)
    pkt_header.checksum = compute_checksum(pkt_header / "Hello, world!\n")
    pkt = pkt_header / "Hello, world!\n"
    s.sendto(bytes(pkt), (receiver_ip, receiver_port))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()

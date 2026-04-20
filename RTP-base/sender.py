import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472
MAX_DATA_CHUNK = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5

TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

def build_packet(pkt_type: int, seq_num: int, payload: bytes) -> bytes:
    """Build packet bytes with a valid checksum."""
    header = PacketHeader(type=pkt_type, seq_num=seq_num, length=len(payload), checksum=0)
    header.checksum = compute_checksum(header / payload)
    return bytes(header / payload)

def parse_and_validate(packet_bytes: bytes):
    """Return (header, payload) if checksum and format are valid, else None."""
    if len(packet_bytes) < HEADER_SIZE:
        return None

    header = PacketHeader(packet_bytes[:HEADER_SIZE])
    payload = packet_bytes[HEADER_SIZE : HEADER_SIZE + header.length]
    if len(payload) != header.length:
        return None

    expected = header.checksum
    tmp_header = PacketHeader(
        type=header.type,
        seq_num=header.seq_num,
        length=header.length,
        checksum=0,
    )
    actual = compute_checksum(tmp_header / payload)
    if actual != expected:
        return None

    return header, payload

def wait_for_start_ack(sock: socket.socket, peer):
    """Send START and wait until ACK(1) is received."""
    start_pkt = build_packet(TYPE_START, 0, b"")
    while True:
        sock.sendto(start_pkt, peer)
        try:
            packet_bytes, _ = sock.recvfrom(MAX_PACKET_SIZE)
            parsed = parse_and_validate(packet_bytes)
            if parsed is None:
                continue
            header, _ = parsed
            if header.type == TYPE_ACK and header.seq_num == 1:
                return
        except socket.timeout:
            # Retransmit START on timeout.
            continue

def transfer_data(sock: socket.socket, peer, chunks: list[bytes], window_size: int):
    """Transfer DATA packets using cumulative ACKs and whole-window retransmission."""
    total_packets = len(chunks)
    if total_packets == 0:
        return 0

    packets = {
        seq_num: build_packet(TYPE_DATA, seq_num, chunk)
        for seq_num, chunk in enumerate(chunks, start=1)
    }
    
    base_seq = 1
    next_seq = 1
    timer_start = time.monotonic()

    while base_seq <= total_packets:
        while next_seq <= total_packets and next_seq < base_seq + window_size:
            sock.sendto(packets[next_seq], peer)
            next_seq += 1

        elapsed = time.monotonic() - timer_start
        remaining = TIMEOUT - elapsed
        if remaining <= 0:
            for seq_num in range(base_seq, next_seq):
                sock.sendto(packets[seq_num], peer)
            timer_start = time.monotonic()
            continue

        sock.settimeout(remaining)
        try:
            packet_bytes, _ = sock.recvfrom(MAX_PACKET_SIZE)
            parsed = parse_and_validate(packet_bytes)
            if parsed is None:
                continue

            header, _ = parsed
            if header.type != TYPE_ACK:
                continue

            ack_seq = header.seq_num
            if base_seq < ack_seq <= total_packets + 1:
                base_seq = ack_seq
                timer_start = time.monotonic()
        except socket.timeout:
            for seq_num in range(base_seq, next_seq):
                sock.sendto(packets[seq_num], peer)
            timer_start = time.monotonic()

    return total_packets

def finish_connection(sock: socket.socket, peer, end_seq: int):
    """Send END and exit on END ACK or 500ms timeout."""
    end_pkt = build_packet(TYPE_END, end_seq, b"")
    sock.sendto(end_pkt, peer)
    sent_at = time.monotonic()

    while time.monotonic() - sent_at < TIMEOUT:
        remaining = TIMEOUT - (time.monotonic() - sent_at)
        sock.settimeout(max(0.0, remaining))
        try:
            packet_bytes, _ = sock.recvfrom(MAX_PACKET_SIZE)
            parsed = parse_and_validate(packet_bytes)
            if parsed is None:
                continue

            header, _ = parsed
            if header.type == TYPE_ACK and header.seq_num == end_seq + 1:
                return
        except socket.timeout:
            return

def sender(receiver_ip, receiver_port, window_size) -> None:
    """Send stdin bytes reliably over UDP using cumulative-ACK semantics."""
    if window_size <= 0:
        raise ValueError("window_size must be a positive integer")

    peer = (receiver_ip, receiver_port)
    data = sys.stdin.buffer.read()
    chunks = [data[i : i + MAX_DATA_CHUNK] for i in range(0, len(data), MAX_DATA_CHUNK)]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        wait_for_start_ack(sock, peer)
        total_packets = transfer_data(sock, peer, chunks, window_size)
        end_seq = total_packets + 1
        finish_connection(sock, peer, end_seq)
    finally:
        sock.close()
    


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

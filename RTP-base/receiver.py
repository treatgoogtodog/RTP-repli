import argparse
import socket

import sys
from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472

TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3


def parse_and_validate(packet_bytes: bytes):
    """Return (header, payload) if packet is valid; otherwise return None."""
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


def build_ack(seq_num: int) -> bytes:
    """Build ACK packet bytes for the provided sequence number."""
    ack_header = PacketHeader(type=TYPE_ACK, seq_num=seq_num, length=0, checksum=0)
    ack_header.checksum = compute_checksum(ack_header / b"")
    return bytes(ack_header / b"")


def handle_start_packet(
    sock: socket.socket,
    sender_addr,
    header: PacketHeader,
    connection_active: bool,
):
    """Handle START semantics.

    TODO:
    - If no active connection and header.seq_num == 0:
      - initialize receiver state for a new connection
      - send ACK(seq=1)
      - mark connection as active
    - If already in an active connection, ignore START packets.
    """
    started_now = False
    if not connection_active and header.seq_num == 0:
        connection_active = True
        started_now = True
        sock.sendto(build_ack(1), sender_addr)

    return connection_active, started_now


def handle_data_packet(
    sock: socket.socket,
    sender_addr,
    header: PacketHeader,
    payload: bytes,
    window_size: int,
    next_expected: int,
    out_of_order_buffer: dict[int, bytes],
):
    """Handle DATA packet with cumulative-ACK behavior.

    TODO:
    - Drop packet if seq_num >= next_expected + window_size.
    - If seq_num < next_expected:
      - this is duplicate/already delivered; send ACK(next_expected).
    - If seq_num == next_expected:
      - append payload to delivered_data
      - increment next_expected
      - while next_expected is present in out_of_order_buffer:
        - flush buffered payload into delivered_data
        - increment next_expected
      - send ACK(next_expected)
    - If next_expected < seq_num < next_expected + window_size:
      - buffer payload if not already buffered
      - send ACK(next_expected)
    """
    if header.seq_num >= next_expected + window_size:
        sock.sendto(build_ack(next_expected), sender_addr)
        return next_expected
    if header.seq_num < next_expected:
        sock.sendto(build_ack(next_expected), sender_addr)
        return next_expected
    if header.seq_num == next_expected:
        in_order_chunks = [payload]
        next_expected += 1
        while next_expected in out_of_order_buffer:
            in_order_chunks.append(out_of_order_buffer.pop(next_expected))
            next_expected += 1
        flush_to_stdout(b"".join(in_order_chunks))
        sock.sendto(build_ack(next_expected), sender_addr)
        return next_expected
    if next_expected < header.seq_num < next_expected + window_size:
        if header.seq_num not in out_of_order_buffer:
            out_of_order_buffer[header.seq_num] = payload
        sock.sendto(build_ack(next_expected), sender_addr)
        return next_expected
    return next_expected

def handle_end_packet(sock: socket.socket, sender_addr, header: PacketHeader, next_expected: int):
    """Handle END packet.

    TODO:
    - For a valid END packet, send ACK(header.seq_num + 1) and signal receiver exit.
    - If END is unexpected for current state, ignore or ACK conservatively based on your policy.
    """
    # Example:
    # sock.sendto(build_ack(header.seq_num + 1), sender_addr)
    if header.seq_num == next_expected:
        sock.sendto(build_ack(header.seq_num + 1), sender_addr)
        return True
    return False

def flush_to_stdout(data: bytes):
    """Write contiguous in-order bytes to stdout exactly once."""
    if data:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def receiver(receiver_ip, receiver_port, window_size):
    """RTP-base receiver skeleton.

    Fill TODOs in helper functions above.
    """
    if window_size <= 0:
        raise ValueError("window_size must be a positive integer")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    connection_active = False
    next_expected = 1
    out_of_order_buffer: dict[int, bytes] = {}

    try:
        while True:
            packet_bytes, sender_addr = sock.recvfrom(MAX_PACKET_SIZE)
            parsed = parse_and_validate(packet_bytes)
            if parsed is None:
                # Corrupted or malformed packet: drop silently.
                continue

            header, payload = parsed

            if header.type == TYPE_START:
                connection_active, started_now = handle_start_packet(
                    sock,
                    sender_addr,
                    header,
                    connection_active,
                )
                if started_now:
                    next_expected = 1
                    out_of_order_buffer.clear()
                continue

            if not connection_active:
                # Ignore non-START packets until a connection is established.
                continue

            if header.type == TYPE_DATA:
                next_expected = handle_data_packet(
                    sock,
                    sender_addr,
                    header,
                    payload,
                    window_size,
                    next_expected,
                    out_of_order_buffer,
                )
                continue

            if header.type == TYPE_END:
                should_exit = handle_end_packet(sock, sender_addr, header, next_expected)
                if should_exit:
                    break
                continue
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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()

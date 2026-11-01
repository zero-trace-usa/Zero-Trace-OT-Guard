"""Synthetic Ethernet/IPv4 Modbus TCP capture; no sockets or device access."""
import struct


def capture(path, messages, port=502):
    data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    seqs = {False: 1, True: 1}
    for index, (response, pdu) in enumerate(messages):
        src, dst = (bytes([10,0,0,2]), bytes([10,0,0,1])) if response else (bytes([10,0,0,1]), bytes([10,0,0,2]))
        payload = struct.pack('!HHHB', index//2+1, 0, len(pdu)+1, 1) + pdu
        tcp = struct.pack('!HHIIBBHHH', port if response else 12345,
                          12345 if response else port, seqs[response], 1, 0x50, 0x18, 65535, 0, 0) + payload
        seqs[response] += len(payload)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(tcp), index, 0, 64, 6, 0, src, dst)
        packet = b'\x00'*12+b'\x08\x00'+ip+tcp
        data += struct.pack('<IIII', index, 0, len(packet), len(packet))+packet
    path.write_bytes(data)
    return path


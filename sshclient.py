from typing import Self
import json
import logging
import struct
from dataclasses import dataclass
from zlib import crc32

import cryptography.hazmat.primitives.asymmetric.dsa
import paramiko

from opcodes import OpCodes

console = logging.getLogger(__name__)


def _check_dsa_parameters(parameters) -> None:
    if parameters.p.bit_length() not in [512, 1024, 2048, 3072, 4096]:
        raise ValueError("p must be exactly 512, 1024, 2048, 3072, or 4096 bits long")
    if parameters.q.bit_length() not in [160, 224, 256]:
        raise ValueError("q must be exactly 160, 224, or 256 bits long")

    if not (1 < parameters.g < parameters.p):
        raise ValueError("g, p don't satisfy 1 < g < p.")


cryptography.hazmat.primitives.asymmetric.dsa._check_dsa_parameters = (
    _check_dsa_parameters
)


@dataclass
class Message:
    main_ver: int = 1
    second_ver: int = 0
    control_code: int = 5  # 6 = bye, 5 = normal message
    reason: int = 0

    serial_number: int | None = None
    op_code: OpCodes | int | None = None

    data: dict | bytes | None = None

    payload_length: int | None = None
    flags: int | None = 0
    error_code: int | None = 0

    checksum: int | None = None

    type: int | None = 1
    ver: int | None = 1

    direct: int | None = 0
    error_code_2: int | None = 0
    reserved: int | None = 0

    small: bool = False

    def __str__(self):
        return repr(self)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        small = False
        main_ver, second_ver, control_code, reason = struct.unpack(
            ">BBBB", bytearray(data[:4])
        )
        sdata = bytearray(data[4:])
        (
            payload_length,
            flags,
            error_code,
            serial_number,
            checksum,
        ) = struct.unpack(">HBBII", sdata[:12]) if len(sdata) >= 12 else [None for i in range(5)]
        if not checksum:
            small = True
        sdata = sdata[12:]
        (
            type,
            ver,
            op_code,
            direct,
            error_code_2,
            reserved,
        ) = (
            struct.unpack(">BBHBBH", sdata[:8])
            if len(sdata[:8]) == 8
            else [None for i in range(6)]
        )
        sdata = sdata[8:]
        try:
            sdata = json.loads(sdata)
        except ValueError:
            pass
        return cls(
            main_ver=main_ver,
            second_ver=second_ver,
            control_code=control_code,
            reason=reason,
            data=sdata,
            payload_length=payload_length,
            flags=flags,
            error_code=error_code,
            serial_number=serial_number,
            checksum=None,
            type=type,
            ver=ver,
            op_code=OpCodes(op_code) if op_code else op_code,
            direct=direct,
            error_code_2=error_code_2,
            reserved=reserved,
            small=small,
        )

    def to_bytes(self) -> bytes:
        if not self.small and self.checksum is None:
            self.checksum = 1516993677
            payload = self.to_bytes()
            self.checksum = crc32(payload)
            result = self.to_bytes()
            return result
        out = struct.pack(
            ">BBBB", self.main_ver, self.second_ver, self.control_code, self.reason
        )
        if self.checksum:
            data = b""
            if self.data:
                if not isinstance(self.data, bytes) and not isinstance(
                    self.data, bytearray
                ):
                    data = json.dumps(self.data, separators=(",", ":")).encode()
                else:
                    data = self.data
            out += struct.pack(
                ">HBBII",
                len(data) + 8,
                self.flags,
                self.error_code,
                self.serial_number,
                self.checksum,
            )
            if self.type is not None:
                out += struct.pack(
                    ">BBHBBH",
                    self.type,
                    self.ver,
                    self.op_code,
                    self.direct,
                    self.error_code_2,
                    self.reserved,
                )
            out += data
        return out


class TPClient:
    @staticmethod
    def ts_factory(*a, **kwa):
        kwa["disabled_algorithms"] = {}
        ts = paramiko.Transport(*a, **kwa)
        ts_so = ts.get_security_options()
        ts_so.kex = ["diffie-hellman-group1-sha1"]
        ts_so.ciphers = ["aes256-cbc"]
        ts_so.key_types = ["ssh-dss"]
        return ts

    def __init__(self, **kwargs):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            username="dropbear",
            transport_factory=self.ts_factory,
            allow_agent=False,
            look_for_keys=False,
            timeout=5,
            **kwargs,
        )
        ts = ssh.get_transport()
        ss = ts.open_channel(
            "direct-tcpip", ("127.0.0.1", 20002), ("127.0.0.1", 22), 0x200000, 0x8000
        )
        self.ssh = ssh
        self.channel = ss
        self.serial_num = 1
        self.write(Message(1, 0, 1, 0, small=True), True, True)
        self.write(Message(1, 0, 2, 0, small=True), False)

    def send(
        self, opcode: OpCodes, data: dict | bytes | None = None, read: bool = True
    ):
        return self.write(Message(op_code=opcode, data=data), read)

    def write(self, data, read=True, asd=False) -> Message | None:
        console.info("SENDING")
        if isinstance(data, Message):
            if data.control_code == 5:
                data.serial_number = self.serial_num
                self.serial_num += 1
            console.debug(data)
            data = data.to_bytes()
        elif type(data) is bytes:
            console.debug(data)
        else:
            if console.level <= logging.DEBUG:
                import base64

                data = base64.b64decode(data.encode())
                console.debug(data)
        try:
            console.info(f"=== {self.channel.send(data)} bytes ===")
        except Exception:
            raise Exception(Message.from_bytes(data))
        if not read:
            return
        thing: Message = None
        if data := self.channel.recv(4):
            console.info("RECEIVING")
            thing: Message = Message.from_bytes(data)
            console.info(f"Control code {thing.control_code}")
            if thing.control_code == 6:
                raise Exception(f"Server said bye: {thing}")
            if thing.control_code not in (1, 2) and (more := self.channel.recv(12)):
                data += more
                thing: Message = Message.from_bytes(data)
                console.info(f"Payload size: {thing.payload_length}")
                if thing.payload_length and (more := self.channel.recv(thing.payload_length)):
                    data += more
                    thing = Message.from_bytes(data)
        else:
            raise EOFError("No data received")
        console.info(f"opcode: {thing.op_code}")
        return thing


def read_data(data: bytes):
    data = bytes(data)
    console.debug(data)
    while data:
        type, length = struct.unpack(">HH", data[:4])
        cdata = data[4 : length + 4]
        yield type, cdata
        data = data[length + 5 :].lstrip(b"\x00")

def encode_data(data: list):
    out = b""
    for type, length, cdata in data:
        out += struct.pack(">HH", type, length)
        out += cdata
        out += b"\xff\x00\x00\x00"
    return out


def read_system_info(data):
    out = {}
    skips = [
        *range(0x208, 0x210),
        *range(0x212, 0x222),
        *range(0x22E, 0x233),
    ]
    items = {
        0x201: ("ip", "ip"),
        0x202: ("mac", "str"),
        0x203: ("hostname", "str"),
        0x204: ("hardwareVersion", "str"),
        0x205: ("softwareVersion", "str"),
        0x206: ("product", "str"),
        0x207: ("company", "str"),
        0x210: ("rebootTime", "int32"),
        0x211: ("wlsRebootTime", "int32"),
        0x222: ("wanCableMatchState", "int8"),
        0x223: ("wanDualNATDetected", "bool"),
        0x224: ("organizationType", "int32"),
        0x225: ("isCEModel", "bool"),
        0x226: ("wanSpeedSupport", "bool"),
        0x227: ("sysUsageSupport", "bool"),
        0x228: ("timeInterval", "int32"),
        0x229: ("lanInfoSupport", "bool"),
        0x22A: ("lanIP", "str"),
        0x22B: ("lanMask", "str"),
        0x22C: ("isIPv6PlusDSLiteOGNHomeShieldSupport", "bool"),
        0x22D: ("isIPv6PlusDSLiteOGNQoSSupport", "bool"),
        0x233: ("isMiFiModel", "bool"),
        0x660: ("wanDialModeType", "int8"),
        0x661: ("wanConnectStatus", "int8"),
    }
    for type, cdata in read_data(data):
        if type in skips:
            continue
        name, type = items[type]
        if type == "str":
            out[name] = cdata.decode()
        elif type == "bool":
            out[name] = bool(struct.unpack("<B", cdata)[0])
        elif type == "int8":
            out[name] = struct.unpack("<B", cdata)[0]
        elif type == "int32":
            out[name] = struct.unpack("<I", cdata)[0]
        elif type == "ip":
            out[name] = ".".join(map(str, struct.unpack("<BBBB", cdata)))
        data = data[length + 5 :].lstrip(b"\x00")
    return out


if __name__ == "__main__":
    from getpass import getpass

    client = TPClient(hostname=input("Hostname/IP: "), password=getpass())

    res = client.write(Message(op_code=OpCodes.TMP_APPV1_OP_SYSTEM_INFO_GET))
    for k, v in read_system_info(res.data).items():
        print(f"{k}: {v}")

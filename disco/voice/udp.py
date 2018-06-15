import struct
import socket
import gevent

from collections import namedtuple

try:
    import nacl.secret
except ImportError:
    print('WARNING: nacl is not installed, voice support is disabled')

from holster.enum import Enum

from disco.util.logging import LoggingClass

AudioCodecs = ('opus',)

PayloadTypes = Enum(OPUS=0x78)

MAX_UINT32 = 4294967295
MAX_SEQUENCE = 65535

RTP_HEADER_ONE_BYTE = (0xBE, 0xDE)


RTPHeader = namedtuple('RTPHeader', [
    'version',
    'padding',
    'extension',
    'csrc_count',
    'marker',
    'payload_type',
    'sequence',
    'timestamp',
    'ssrc',
])

VoiceData = namedtuple('VoiceData', [
    'client',
    'user_id',
    'payload_type',
    'rtp',
    'data',
])


class UDPVoiceClient(LoggingClass):
    def __init__(self, vc):
        super(UDPVoiceClient, self).__init__()
        self.vc = vc

        # The underlying UDP socket
        self.conn = None

        # Connection information
        self.ip = None
        self.port = None
        self.connected = False

        # Voice information
        self.sequence = 0
        self.timestamp = 0

        self._nonce = 0
        self._run_task = None
        self._secret_box = None

        # Buffer used for encoding/sending frames
        self._header = bytearray(12)
        self._header[0] = 2 << 6  # Only RTP Version set in the first byte of the header, 0x80
        self._header[1] = PayloadTypes.OPUS.value

    def increment_timestamp(self, by):
        self.timestamp += by
        if self.timestamp > MAX_UINT32:
            self.timestamp = 0

    def setup_encryption(self, encryption_key):
        self._secret_box = nacl.secret.SecretBox(encryption_key)

    def send_frame(self, frame, sequence=None, timestamp=None, incr_timestamp=None):
        # Convert the frame to a bytearray
        frame = bytearray(frame)

        # Pack the rtc header into our buffer
        struct.pack_into('>H', self._header, 2, sequence or self.sequence)
        struct.pack_into('>I', self._header, 4, timestamp or self.timestamp)
        struct.pack_into('>i', self._header, 8, self.vc.ssrc)

        if self.vc.mode == 'xsalsa20_poly1305_lite':
            # Use an incrementing number as a nonce, only first 4 bytes of the nonce is padded on
            self._nonce += 1
            if self._nonce > MAX_UINT32:
                self._nonce = 0

            nonce = bytearray(24)
            struct.pack_into('>I', nonce, 0, self._nonce)
            nonce_padding = nonce[:4]
        elif self.vc.mode == 'xsalsa20_poly1305_suffix':
            # Generate a nonce
            nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            nonce_padding = nonce
        elif self.vc.mode == 'xsalsa20_poly1305':
            # Nonce is the header
            nonce = bytearray(24)
            nonce[:12] = self._header
            nonce_padding = None
        else:
            raise Exception('The voice mode, {}, isn\'t supported.'.format(self.vc.mode))

        # Encrypt the payload with the nonce
        raw = self._secret_box.encrypt(bytes(frame), bytes(nonce)).ciphertext

        # Pad the payload with the nonce, if applicable
        if nonce_padding:
            raw += nonce_padding

        # Send the header (sans nonce padding) plus the payload
        self.send(self._header + raw)

        # Increment our sequence counter
        self.sequence += 1
        if self.sequence >= MAX_SEQUENCE:
            self.sequence = 0

        # Increment our timestamp (if applicable)
        if incr_timestamp:
            self.timestamp += incr_timestamp

    def run(self):
        while True:
            data, addr = self.conn.recvfrom(4096)

            # Data cannot be less than the bare minimum, just ignore
            if len(data) <= 12:
                continue

            first, second, sequence, timestamp, ssrc = struct.unpack_from('>BBHII', data)

            rtp = RTPHeader(
                version=first >> 6,
                padding=(first >> 5) & 1,
                extension=(first >> 4) & 1,
                csrc_count=first & 0x0F,
                marker=second >> 7,
                payload_type=second & 0x7F,
                sequence=sequence,
                timestamp=timestamp,
                ssrc=ssrc,
            )

            # Check if rtp version is 2
            if rtp.version != 2:
                continue

            payload_type = PayloadTypes.get(rtp.payload_type)

            # Unsupported payload type received
            if not payload_type:
                continue

            nonce = bytearray(24)
            if self.vc.mode == 'xsalsa20_poly1305_lite':
                nonce[:4] = data[-4:]
                data = data[:-4]
            elif self.vc.mode == 'xsalsa20_poly1305_suffx':
                nonce[:24] = data[-24:]
                data = data[:-24]
            elif self.vc.mode == 'xsalsa20_poly1305':
                nonce[:12] = data[:12]
            else:
                continue

            try:
                data = self._secret_box.decrypt(bytes(data[12:]), bytes(nonce))
            except Exception:
                continue

            # RFC3550 Section 5.1 (Padding)
            if rtp.padding:
                padding_amount, = struct.unpack_from('>B', data[:-1])
                data = data[-padding_amount:]

            if rtp.extension:
                # RFC5285 Section 4.2: One-Byte Header
                rtp_extension_header = struct.unpack_from('>BB', data)
                if rtp_extension_header == RTP_HEADER_ONE_BYTE:
                    data = data[2:]

                    fields_amount, = struct.unpack_from('>H', data)
                    fields = []

                    offset = 4
                    for i in range(fields_amount):
                        first_byte, = struct.unpack_from('>B', data[offset])
                        offset += 1

                        rtp_extension_identifer = first_byte & 0xF
                        rtp_extension_len = ((first_byte >> 4) & 0xF) + 1

                        # Ignore data if identifer == 15, so skip if this is set as 0
                        if rtp_extension_identifer:
                            fields.append(data[offset:offset + rtp_extension_len])

                        offset += rtp_extension_len

                        # skip padding
                        while data[offset] == 0:
                            offset += 1

                    if len(fields):
                        fields.append(data[offset:])
                        data = b''.join(fields)
                    else:
                        data = data[offset:]

            # RFC3550 Section 5.3: Profile-Specific Modifications to the RTP Header
            # clients send it sometimes, definitely on fresh connects to a server, dunno what to do here
            if rtp.marker:
                continue

            payload = VoiceData(
                client=self.vc,
                payload_type=payload_type.name,
                user_id=self.vc.audio_ssrcs.get(rtp.ssrc, None),
                rtp=rtp,
                data=data,
            )

            self.vc.client.gw.events.emit('VoiceData', payload)

    def send(self, data):
        self.conn.sendto(data, (self.ip, self.port))

    def disconnect(self):
        self._run_task.kill()

    def connect(self, host, port, timeout=10, addrinfo=None):
        self.ip = socket.gethostbyname(host)
        self.port = port

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if addrinfo:
            ip, port = addrinfo
        else:
            # Send discovery packet
            packet = bytearray(70)
            struct.pack_into('>I', packet, 0, self.vc.ssrc)
            self.send(packet)

            # Wait for a response
            try:
                data, addr = gevent.spawn(lambda: self.conn.recvfrom(70)).get(timeout=timeout)
            except gevent.Timeout:
                return (None, None)

            # Read IP and port
            ip = str(data[4:]).split('\x00', 1)[0]
            port = struct.unpack('<H', data[-2:])[0]

        # Spawn read thread so we don't max buffers
        self.connected = True
        self._run_task = gevent.spawn(self.run)

        return (ip, port)

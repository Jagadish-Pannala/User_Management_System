import time
import uuid
import random

def generate_uuid7():
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF  # 6 bytes timestamp
    ts_bytes = ts_ms.to_bytes(6, byteorder='big')
    rand_bytes = random.getrandbits(80).to_bytes(10, byteorder='big')  # 10 bytes random
    uuid_bytes = ts_bytes + rand_bytes
    return str(uuid.UUID(bytes=uuid_bytes))
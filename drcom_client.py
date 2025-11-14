import asyncio
import logging
import signal
import socket
import struct
import time
from dataclasses import dataclass
from hashlib import md5
import random
import fcntl
from logging.handlers import RotatingFileHandler
from typing import Optional, Tuple
import os


@dataclass
class DrComUserConfig:
    server: str = '10.100.61.3'
    username: str = 'zhangtw9922'
    password: str = 'zhang20041016'
    host_ip: str = '49.140.116.165'
    mac: str = '58:11:22:84:46:5B'
    wan: str = 'wan'
    host_name: str = 'XiaoMiR3G'
    host_os: str = 'ImmortalWrt'
    primary_dns: str = '10.10.10.10'
    log_path: str = '/tmp/log/drcom_client.log'
    log_level: str = 'INFO'


@dataclass
class DrComInternalConfig:
    CONTROLCHECKSTATUS: bytes = b'\x20'
    ADAPTERNUM: bytes = b'\x03'
    IPDOG: bytes = b'\x01'
    dhcp_server: str = '0.0.0.0'
    AUTH_VERSION: bytes = b'\x68\x00'
    KEEP_ALIVE_VERSION: bytes = b'\xdc\x02'
    bind_ip: str = '0.0.0.0'
    unlimited_retry: bool = True
    challenge_max_retries: int = 3
    login_max_retries: int = 3
    CLIENT_PORT: int = 61440
    RECV_BUFSIZE: int = 1024
    CHALLENGE_TIMEOUT: float = 2.0
    LOGIN_TIMEOUT: float = 3.0
    KEEPALIVE_INIT_TIMEOUT: float = 2.0
    KEEPALIVE_MAIN_TIMEOUT: float = 3.0
    BUFFER_EMPTY_TIMEOUT: float = 0.3
    RETRY_INTERVAL: float = 28.0
    USERNAME_MAX_LEN: int = 36
    PASSWORD_MAX_LEN: int = 32
    HOSTNAME_MAX_LEN: int = 32


class ChallengeException(Exception): pass
class LoginException(Exception): pass


class DrComClient:
    __slots__ = [
        '_user_config', '_internal_config', '_socket', '_salt', '_logger',
        '_keep_alive_task', '_running', '_loop', '_mac_int', '_mac_bytes',
        '_username_bytes', '_password_bytes', '_hostname_bytes', '_dns_bytes',
        '_ip_bytes', '_salt_cache'
    ]

    def __init__(self, user_config: DrComUserConfig, internal_config: Optional[DrComInternalConfig] = None):
        self._user_config = user_config
        self._internal_config = internal_config or DrComInternalConfig()
        self._mac_int = int(self._user_config.mac.replace(':', ''), 16)
        self._mac_bytes = bytes.fromhex(self._user_config.mac.replace(':', ''))
        self._username_bytes = self._user_config.username.encode('utf-8')
        self._password_bytes = self._user_config.password.encode('utf-8')
        self._hostname_bytes = self._user_config.host_name.encode('utf-8')[:self._internal_config.HOSTNAME_MAX_LEN]
        self._dns_bytes = socket.inet_aton(self._user_config.primary_dns)
        self._ip_bytes = socket.inet_aton(self._user_config.host_ip)
        self._salt = b''
        self._salt_cache = b''
        self._socket: Optional[socket.socket] = None
        self._keep_alive_task: Optional[asyncio.Task] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._setup_logging()

    def _setup_logging(self):
        try:
            log_dir = os.path.dirname(self._user_config.log_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = RotatingFileHandler(
                self._user_config.log_path,
                maxBytes=50*1024,
                backupCount=1,
                encoding='utf-8'
            )
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self._logger = logging.getLogger(f"drcom_{id(self)}")
            level = getattr(logging, self._user_config.log_level.upper(), logging.INFO)
            self._logger.setLevel(level)
            self._logger.addHandler(file_handler)
            self._logger.addHandler(console_handler)
        except Exception:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            self._logger = logging.getLogger(__name__)
            self._logger.error("Failed to setup rotating log, using basic config")

    async def _bind_socket(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setblocking(False)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            bind_ip = self._internal_config.bind_ip if self._user_config.wan == '' else await self._bind_wan()
            self._socket.bind((bind_ip, self._internal_config.CLIENT_PORT))
            
            if bind_ip != '0.0.0.0' and bind_ip != self._user_config.host_ip:
                self._logger.warning(f"Inconsistent IP configuration: host_ip='{self._user_config.host_ip}' != bind_ip='{bind_ip}'")
            
            self._loop = asyncio.get_running_loop()
            self._logger.info(f"Socket bound to {bind_ip}:{self._internal_config.CLIENT_PORT}")
        except Exception as e:
            self._logger.error(f"Socket binding failed: {e}")
            raise

    async def _bind_wan(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifreq = struct.pack('16sH14s', self._user_config.wan[:15].encode(), 0, b'\x00' * 14)
            try:
                res = fcntl.ioctl(s.fileno(), 0x8915, ifreq)
                ip = socket.inet_ntoa(res[20:24])
            except OSError:
                s.connect((self._user_config.server, 1))
                ip = s.getsockname()[0]
            finally:
                s.close()
            return ip
        except Exception as e:
            self._logger.error(f"Failed to get WAN IP for '{self._user_config.wan}': {e}")
            return '0.0.0.0'

    @staticmethod
    def _md5sum(s: bytes) -> bytes:
        return md5(s).digest()

    @staticmethod
    def _dump(n: int) -> bytes:
        s = f'{n:x}'
        return bytes.fromhex('0' + s if len(s) & 1 else s)

    def _mkpkt(self, salt: bytes, mac: int) -> bytes:
        usr = self._username_bytes[:self._internal_config.USERNAME_MAX_LEN]
        pwd = self._password_bytes
        
        md5_1 = self._md5sum(b'\x03\x01' + salt + pwd)
        data = bytearray()
        data.extend(b'\x03\x01\x00')
        data.append(len(usr) + 20)
        data.extend(md5_1)
        data.extend(usr.ljust(self._internal_config.USERNAME_MAX_LEN, b'\x00'))
        data.extend(self._internal_config.CONTROLCHECKSTATUS)
        data.extend(self._internal_config.ADAPTERNUM)
        
        mac_xor = int.from_bytes(data[4:10], 'big') ^ mac
        data.extend(mac_xor.to_bytes(6, 'big'))
        data.extend(self._md5sum(b"\x01" + pwd + salt + b'\x00' * 4))
        data.append(0x01)
        data.extend(self._ip_bytes)
        data.extend(b'\x00' * 12)
        data.extend(self._md5sum(bytes(data) + b'\x14\x00\x07\x0b')[:8])
        data.extend(self._internal_config.IPDOG)
        data.extend(b'\x00' * 4)
        data.extend(self._hostname_bytes.ljust(self._internal_config.HOSTNAME_MAX_LEN, b'\x00'))
        data.extend(self._dns_bytes)
        data.extend(socket.inet_aton(self._internal_config.dhcp_server))
        data.extend(b'\x00' * 12 + b'\x94\x00\x00\x00\x06\x00\x00\x00\x02\x00\x00\x00\xf0\x23\x00\x00\x02\x00\x00\x00')
        data.extend(b'\x44\x72\x43\x4f\x4d\x00\xcf\x07\x68' + b'\x00' * 55)
        data.extend(b'\x33\x64\x63\x37\x39\x66\x35\x32\x31\x32\x65\x38\x31\x37\x30\x61\x63\x66\x61\x39\x65\x63\x39\x35\x66\x31\x64\x37\x34\x39\x31\x36\x35\x34\x32\x62\x65\x37\x62\x31')
        data.extend(b'\x00' * 24)
        data.extend(self._internal_config.AUTH_VERSION)
        data.append(0x00)
        data.append(len(pwd))
        
        pwd_len = len(pwd)
        ror_result = bytearray(pwd_len)
        for i in range(pwd_len):
            val = md5_1[i] ^ pwd[i]
            ror_result[i] = ((val << 3) & 0xFF) | (val >> 5)
        data.extend(ror_result)
        
        data.extend(b'\x02\x0c')
        checksum_data = bytes(data) + b'\x01\x26\x07\x11\x00\x00' + mac.to_bytes(6, 'big')
        data.extend(self._checksum(checksum_data))
        data.extend(b'\x00\x00')
        data.extend(mac.to_bytes(6, 'big'))
        pad_len = len(pwd) // 4 if (len(pwd) % 4) != 0 else 0
        data.extend(b'\x00' * pad_len + b'\x60\xa2' + b'\x00' * 28)
        return bytes(data)

    @staticmethod
    def _checksum(s: bytes) -> bytes:
        padding_needed = (4 - len(s) % 4) % 4
        padded_s = s + b'\x00' * padding_needed if padding_needed else s
            
        ret = 1234
        for i in range(0, len(padded_s), 4):
            val = struct.unpack('<I', padded_s[i:i+4])[0]
            ret ^= val
        ret = (1968 * ret) & 0xffffffff
        return struct.pack('<I', ret)

    async def _challenge(self, svr: str, ran: float) -> bytes:
        max_retries = self._internal_config.challenge_max_retries
        challenge_pkt = b"\x01\x02" + struct.pack("<H", int(ran) % 0xFFFF) + b"\x09" + b"\x00" * 15
        
        if self._loop is None:
            raise ChallengeException("Event loop not initialized")
            
        for attempt in range(max_retries):
            try:
                if self._socket is None:
                    raise ChallengeException("Socket not initialized")
                await self._loop.sock_sendto(self._socket, challenge_pkt, (svr, self._internal_config.CLIENT_PORT))
                
                data, address = await asyncio.wait_for(
                    self._loop.sock_recvfrom(self._socket, self._internal_config.RECV_BUFSIZE),
                    timeout=self._internal_config.CHALLENGE_TIMEOUT
                )
                
                if address[0] == svr and address[1] == self._internal_config.CLIENT_PORT and data[0] == 2:
                    salt = data[4:8]
                    self._salt_cache = salt
                    return salt
                    
            except asyncio.TimeoutError:
                if attempt == max_retries - 1:
                    raise ChallengeException("Challenge max retries exceeded")
            except Exception as e:
                if attempt == max_retries - 1:
                    raise ChallengeException(f"Challenge failed: {e}")
            
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5)
        
        raise ChallengeException("Challenge failed after all retries")

    def _keep_alive_package_builder(self, number: int, random_val: bytes, tail: bytes, type_val: int = 1, first: bool = False) -> bytes:
        data = bytearray(48)
        data[0] = 0x07
        data[1] = number
        data[2:5] = b'\x28\x00\x0b'
        data[5] = type_val
        data[6:8] = b'\x0f\x27' if first else self._internal_config.KEEP_ALIVE_VERSION
        data[8:14] = b'\x2f\x12\x00\x00\x00\x00'
        data[14:18] = tail
        if type_val == 3:
            data[22:26] = self._ip_bytes
        return bytes(data)

    async def _keep_alive1(self, salt: bytes, tail: bytes, svr: str):
        try:
            if self._socket is None or self._loop is None:
                self._logger.error('[keep_alive1] Socket or event loop not initialized')
                return

            md5_result = self._md5sum(b'\x03\x01' + salt + self._password_bytes)
            data = bytearray(23)
            data[0] = 0xFF
            data[1:17] = md5_result
            data[17:21] = tail
            data[21:23] = struct.pack('!H', int(time.time()) % 0xFFFF)
            await self._loop.sock_sendto(self._socket, data, (svr, self._internal_config.CLIENT_PORT))
        except Exception as e:
            self._logger.error(f'[keep_alive1] error: {e}')

    async def _keep_alive2(self, salt: bytes, tail: bytes, svr: str):
        try:
            if self._loop is None or self._socket is None:
                raise Exception("Event loop or socket not initialized")
            svr_num, ran = 0, random.randint(0, 0xFFFF) + random.randint(1, 10)
            packet = self._keep_alive_package_builder(svr_num, self._dump(ran), b'\x00' * 4, 1, True)
            max_attempts = 5
            
            for attempt in range(max_attempts):
                await self._loop.sock_sendto(self._socket, packet, (svr, self._internal_config.CLIENT_PORT))
                try:
                    data, address = await asyncio.wait_for(
                        self._loop.sock_recvfrom(self._socket, self._internal_config.RECV_BUFSIZE),
                        timeout=self._internal_config.KEEPALIVE_INIT_TIMEOUT
                    )
                    if data.startswith(b'\x07\x00\x28\x00') or data.startswith(b'\x07' + svr_num.to_bytes(1, 'big') + b'\x28\x00'):
                        break
                    elif data[0] == 0x07 and data[2] == 0x10:
                        svr_num += 1
                        packet = self._keep_alive_package_builder(svr_num, self._dump(ran), b'\x00' * 4, 1, False)
                    else:
                        continue
                except asyncio.TimeoutError:
                    if attempt == max_attempts - 1:
                        raise Exception("keep-alive2 initialization failed")
                    await asyncio.sleep(0.5)

            tail_val = tail
            i = svr_num
            while self._running:
                try:
                    ran += random.randint(1, 10)
                    packet = self._keep_alive_package_builder(i, self._dump(ran), tail_val, 1, False)
                    await self._loop.sock_sendto(self._socket, packet, (svr, self._internal_config.CLIENT_PORT))
                    
                    data, address = await asyncio.wait_for(
                        self._loop.sock_recvfrom(self._socket, self._internal_config.RECV_BUFSIZE),
                        timeout=self._internal_config.KEEPALIVE_MAIN_TIMEOUT
                    )
                    tail_val = data[16:20]
                    
                    ran += random.randint(1, 10)
                    packet = self._keep_alive_package_builder(i + 1, self._dump(ran), tail_val, 3, False)
                    await self._loop.sock_sendto(self._socket, packet, (svr, self._internal_config.CLIENT_PORT))
                    
                    data, address = await asyncio.wait_for(
                        self._loop.sock_recvfrom(self._socket, self._internal_config.RECV_BUFSIZE),
                        timeout=self._internal_config.KEEPALIVE_MAIN_TIMEOUT
                    )
                    tail_val = data[16:20]
                    i = (i + 2) % 0xFF
                    
                    await asyncio.sleep(20)
                    await self._keep_alive1(salt, tail_val, svr)
                    
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self._logger.error(f'Keep-alive error: {e}')
                    await asyncio.sleep(5)
                    continue
        except Exception as e:
            self._logger.error(f'[keep_alive2] fatal error: {e}')
            raise

    async def _login(self, svr: str) -> bytes:
        if self._loop is None:
            raise LoginException("Event loop not initialized")
            
        max_retries = self._internal_config.login_max_retries
        for attempt in range(max_retries):
            try:
                if self._socket is None:
                    raise LoginException("Socket not initialized")
                if self._salt_cache and attempt == 0:
                    salt = self._salt_cache
                else:
                    salt = await self._challenge(svr, time.time() + random.randint(0xF, 0xFF))
                
                self._salt = salt
                packet = self._mkpkt(salt, self._mac_int)
                await self._loop.sock_sendto(self._socket, packet, (svr, self._internal_config.CLIENT_PORT))
                
                data, address = await asyncio.wait_for(
                    self._loop.sock_recvfrom(self._socket, self._internal_config.RECV_BUFSIZE),
                    timeout=self._internal_config.LOGIN_TIMEOUT
                )
                
                if address[0] == svr and address[1] == self._internal_config.CLIENT_PORT and data[0] == 4:
                    return data[23:39]
                    
                if attempt < max_retries - 1:
                    await asyncio.sleep(1.5)
                    continue
                else:
                    raise LoginException("Login failed after max retries")
                    
            except asyncio.TimeoutError:
                if attempt == max_retries - 1:
                    raise LoginException("Login timeout after all retries")
                await asyncio.sleep(1.5)
            except ChallengeException as e:
                if attempt == max_retries - 1:
                    raise LoginException(f"Challenge failed: {e}")
                await asyncio.sleep(1.5)
        
        raise LoginException("Login failed after all attempts")

    async def _empty_socket_buffer(self):
        try:
            if self._loop is None or self._socket is None:
                return
            while True:
                try:
                    await asyncio.wait_for(
                        self._loop.sock_recvfrom(self._socket, self._internal_config.RECV_BUFSIZE),
                        timeout=self._internal_config.BUFFER_EMPTY_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    break
        except Exception:
            pass

    def _schedule_cleanup(self, signame):
        self._logger.warning(f"Received signal {signame}")
        if self._running:
            asyncio.create_task(self.cleanup())

    async def cleanup(self):
        if not self._running:
            return
        self._running = False
        if self._keep_alive_task and not self._keep_alive_task.done():
            self._keep_alive_task.cancel()
            try:
                await asyncio.wait_for(self._keep_alive_task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None

    async def run(self):
        self._running = True
        loop = asyncio.get_running_loop()
        
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._schedule_cleanup, sig.name)
        
        try:
            await self._bind_socket()
            self._logger.info(f"Starting auth to {self._user_config.server} as {self._user_config.username}")
            
            while self._running:
                try:
                    package_tail = await self._login(self._user_config.server)
                    await self._empty_socket_buffer()
                    await self._keep_alive1(self._salt, package_tail, self._user_config.server)
                    
                    self._keep_alive_task = asyncio.create_task(
                        self._keep_alive2(self._salt, package_tail, self._user_config.server)
                    )
                    await self._keep_alive_task
                    
                except (LoginException, ChallengeException) as e:
                    self._logger.error(f"Auth failed: {e}")
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self._logger.error(f"Unexpected error: {e}")

                if self._running and self._internal_config.unlimited_retry:
                    await asyncio.sleep(self._internal_config.RETRY_INTERVAL)
                else:
                    break
                    
        except Exception as e:
            self._logger.error(f"Fatal error: {e}")
        finally:
            await self.cleanup()


def main():
    try:
        client = DrComClient(DrComUserConfig())
        asyncio.run(client.run())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Critical error: {e}")


if __name__ == "__main__":
    main()
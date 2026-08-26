#Libraries
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
import paramiko
import socket
import platform
import threading
from dotenv import load_dotenv
import os

load_dotenv() #loading environment variables from .env file

#Constants
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

# Load the private key from the file
host_key = paramiko.RSAKey.from_private_key_file(os.getenv('SERVER_KEY_PATH'))

#Loggers & Logging Files
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2_000_000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2_000_000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

#Emulated Shell
def emulated_shell(channel, client_ip):
    channel.send(b'corporate-jumpbox2$ ')
    command = b""
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()

        command += char

        if char == b'\r':
            if command.strip() == b'exit':
                response = b'\n Goodbye! \n'
                channel.close()
            elif command.strip() == b'pwd':
                response = b"\n/usr/local\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            elif command.strip() == b'whoami':
                response = b"\ncorpuser1\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            elif command.strip() == b'ls':
                response = b"\njumpbox1.conf  backup.sh  logs\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            elif command.strip() == b'cat jumpbox1.conf':
                response = b"\nhost=deebodah.com\nport=22\nuser=admin\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            elif command.strip() == b'uname -a':
                response = b"\nLinux corporate-jumpbox2 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            elif command.strip() == b'cat /etc/passwd':
                response = b"\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\ncorpuser1:x:1001:1001::/home/corpuser1:/bin/bash\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            elif command.strip() == b'ifconfig' or command.strip() == b'ip a':
                response = b"\neth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> inet 192.168.1.105\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            elif command.strip() == b'id':
                response = b"\nuid=1001(corpuser1) gid=1001(corpuser1) groups=1001(corpuser1)\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            elif command.strip().startswith(b'wget') or command.strip().startswith(b'curl'):
                response = b"\nbash: permission denied\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            elif command.strip() == b'ps aux':
                response = b"\nUSER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  16952  1084 ?        Ss   08:00   0:00 /sbin/init\ncorpuser1  512  0.0  0.1  13456   980 pts/0    Ss   09:00   0:00 -bash\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            else:
                response = b"\n" + bytes(command.strip()) + b": command not found\r\n"
                creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {client_ip} | {command.strip()}')
            channel.send(response)
            channel.send(b'corporate-jumpbox2$ ')
            command = b""

#SSH Server + Sockets
class Server(paramiko.ServerInterface):

    def __init__ (self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
    
    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        
    def get_allowed_auths(self, username):
        return 'password'
    
    def check_auth_password(self, username, password):
        funnel_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {self.client_ip} | {username} | {password}')
        creds_logger.info(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {self.client_ip} | {username} | {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True
    
def client_handle(client, addr, username, password):
    client_ip = addr[0]
    device_type = platform.system() #Capture device type
    print(f"{client_ip} has connected to the server using device: {device_type}.")


    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)

        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")
            
        standard_banner = "Welcome to Ubuntu 22.04 LTS \r\n\r\n"
        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        print(error)
        print("!!! Error !!!")
    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("!!! Error !!!")



#Provision SSH-based honeypot
def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print(error)

if __name__ == '__main__':
    honeypot('127.0.0.1', 2223, username = None, password = None)
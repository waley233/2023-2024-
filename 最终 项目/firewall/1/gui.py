import tkinter as tk
from tkinter import messagebox
import threading
import subprocess
import re

def is_valid_ip(ip):
    # 使用正则表达式验证IP地址格式
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return pattern.match(ip) is not None

def is_valid_port(port):
    # 端口号应该是一个介于0和65535之间的整数
    try:
        return 0 <= int(port) <= 65535
    except ValueError:
        return False

def start_firewall(protocol, source_ip, dest_ip, source_port, dest_port):
    try:
        firewall_script = 'firewall.py'  # 前一个脚本的文件名
        subprocess.run(['python3', firewall_script, protocol, source_ip, dest_ip, source_port, dest_port], check=True)
        messagebox.showinfo("Success", "Firewall rules applied successfully!")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to apply firewall rules:\n{e}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def on_start_button_click():
    protocol = protocol_var.get()
    source_ip = source_ip_entry.get()
    dest_ip = dest_ip_entry.get()
    source_port = source_port_entry.get()
    dest_port = dest_port_entry.get()
    
    # 输入验证
    if not is_valid_ip(source_ip):
        messagebox.showerror("Error", "Invalid source IP address format.")
        return
    if not is_valid_ip(dest_ip):
        messagebox.showerror("Error", "Invalid destination IP address format.")
        return
    if not is_valid_port(source_port):
        messagebox.showerror("Error", "Invalid source port number.")
        return
    if not is_valid_port(dest_port):
        messagebox.showerror("Error", "Invalid destination port number.")
        return
    
    # 开始防火墙线程
    threading.Thread(target=start_firewall, args=(protocol, source_ip, dest_ip, source_port, dest_port)).start()

root = tk.Tk()
root.title("Firewall Settings")

# 创建输入字段和标签
tk.Label(root, text="Select Protocol:").pack()
protocol_var = tk.StringVar(value="TCP")
tk.Radiobutton(root, text="TCP", variable=protocol_var, value="TCP").pack()
tk.Radiobutton(root, text="UDP", variable=protocol_var, value="UDP").pack()

tk.Label(root, text="Source IP Address:").pack()
source_ip_entry = tk.Entry(root)
source_ip_entry.pack()

tk.Label(root, text="Destination IP Address:").pack()
dest_ip_entry = tk.Entry(root)
dest_ip_entry.pack()

tk.Label(root, text="Source Port:").pack()
source_port_entry = tk.Entry(root)
source_port_entry.pack()

tk.Label(root, text="Destination Port:").pack()
dest_port_entry = tk.Entry(root)
dest_port_entry.pack()

# 创建开始按钮
start_button = tk.Button(root, text="Start Firewall", command=on_start_button_click)
start_button.pack()

root.mainloop()


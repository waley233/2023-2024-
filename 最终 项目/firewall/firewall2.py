import subprocess
import sys
import tkinter as tk
from tkinter import messagebox


def set_iptables_rule(protocol, src_ip, dst_ip, src_port, dst_port, action="DROP"):
    rule = [
        "iptables", "-I", "INPUT", "-p", protocol,
        "--source", src_ip, "--destination", dst_ip,
        "--sport", str(src_port), "--dport", str(dst_port), "-j", action
    ]
    subprocess.run(rule, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def clear_iptables_rules():
    subprocess.run(["iptables", "-F"], stdout=subprocess.PIPE)


def on_submit():
    protocol = protocol_var.get()
    src_ip = src_ip_var.get()
    dst_ip = dst_ip_var.get()
    src_port = src_port_var.get()
    dst_port = dst_port_var.get()
    
    set_iptables_rule(protocol, src_ip, dst_ip, src_port, dst_port)
    messagebox.showinfo("Success", "The rule has been set.")


def on_clear():
    clear_iptables_rules()
    messagebox.showinfo("Cleared", "All rules have been cleared.")


# GUI
root = tk.Tk()
root.title("Firewall Settings")

protocol_var = tk.StringVar()
src_ip_var = tk.StringVar()
dst_ip_var = tk.StringVar()
src_port_var = tk.StringVar()
dst_port_var = tk.StringVar()

tk.Label(root, text="Protocol (tcp/udp)").grid(row=0, column=0)
tk.Entry(root, textvariable=protocol_var).grid(row=0, column=1)

tk.Label(root, text="Source IP").grid(row=1, column=0)
tk.Entry(root, textvariable=src_ip_var).grid(row=1, column=1)

tk.Label(root, text="Destination IP").grid(row=2, column=0)
tk.Entry(root, textvariable=dst_ip_var).grid(row=2, column=1)

tk.Label(root, text="Source Port").grid(row=3, column=0)
tk.Entry(root, textvariable=src_port_var).grid(row=3, column=1)

tk.Label(root, text="Destination Port").grid(row=4, column=0)
tk.Entry(root, textvariable=dst_port_var).grid(row=4, column=1)

tk.Button(root, text="Submit", command=on_submit).grid(row=5, column=0)
tk.Button(root, text="Clear Rules", command=on_clear).grid(row=5, column=1)

root.mainloop()


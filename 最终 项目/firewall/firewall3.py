import subprocess
import sys
import argparse
import tkinter as tk
from tkinter import messagebox

def set_iptables_rule(chain, protocol, src_ip, dst_ip, src_port, dst_port, action="DROP"):
    rule = [
        "sudo", "iptables", "-I", chain, "-p", protocol,
        "--source", src_ip, "--destination", dst_ip,
        "--sport", str(src_port), "--dport", str(dst_port), "-j", action
    ]
    subprocess.run(rule, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def clear_iptables_rules():
    for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
        subprocess.run(["sudo", "iptables", "-F", chain], stdout=subprocess.PIPE)

def on_submit():
    protocol = protocol_var.get()
    src_ip = src_ip_var.get()
    dst_ip = dst_ip_var.get()
    src_port = src_port_var.get()
    dst_port = dst_port_var.get()
    action = action_var.get()

    for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
        set_iptables_rule(chain, protocol, src_ip, dst_ip, src_port, dst_port, action)
    messagebox.showinfo("Success", "The rules have been set.")

def on_clear():
    clear_iptables_rules()
    messagebox.showinfo("Cleared", "All rules have been cleared.")

def main(args):
    if args:
        # If arguments are provided via the command line, apply them directly.
        for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
            set_iptables_rule(chain, args.protocol, args.src_ip, args.dst_ip, args.src_port, args.dst_port, args.action)
        print("The rules have been set.")
    else:
        # GUI
        root = tk.Tk()
        root.title("Firewall Settings")

        global protocol_var, src_ip_var, dst_ip_var, src_port_var, dst_port_var, action_var
        protocol_var = tk.StringVar()
        src_ip_var = tk.StringVar()
        dst_ip_var = tk.StringVar()
        src_port_var = tk.StringVar()
        dst_port_var = tk.StringVar()
        action_var = tk.StringVar()

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

        tk.Label(root, text="Action (DROP/ACCEPT)").grid(row=5, column=0)
        tk.Entry(root, textvariable=action_var).grid(row=5, column=1)

        tk.Button(root, text="Submit", command=on_submit).grid(row=6, column=0)
        tk.Button(root, text="Clear Rules", command=on_clear).grid(row=6, column=1)

        root.mainloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Set iptables rules for inbound, outbound, and forwarding.")
    parser.add_argument("--protocol", type=str, help="Protocol (tcp/udp)")
    parser.add_argument("--src_ip", type=str, help="Source IP address")
    parser.add_argument("--dst_ip", type=str, help="Destination IP address")
    parser.add_argument("--src_port", type=int, help="Source port number")
    parser.add_argument("--dst_port", type=int, help="Destination port number")
    parser.add_argument("--action", type=str, default="DROP", help="Action to take (DROP/ACCEPT)")

    args, unknown = parser.parse_known_args()

    # Run the main function if no arguments were provided (then we use the GUI).
    # Otherwise, use the command line arguments.
    if len(sys.argv) == 1:
        main(None)
    else:
        main(args)

#python script_name.py --protocol tcp --src_ip 192.168.23.128 --dst_ip 192.168.23.129 --src_port 23 --dst_port 23 --action DROP
#sudo iptables -F



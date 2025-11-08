#!/usr/bin/env python3
import os
os.environ["TK_SILENCE_DEPRECATION"] = "1"  # silence macOS Tk warning for Tkinter

import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox


# ---------- Networking logic ----------

def get_ipv4_class(ip_str: str) -> str:
    """Return IPv4 class A/B/C/D/E or special for 127.x.x.x."""
    try:
        first_octet = int(ip_str.split('.')[0])
    except Exception:
        return "Unknown"
    if 1 <= first_octet <= 126:
        return "Class A"
    if first_octet == 127:
        return "Loopback / Reserved"
    if 128 <= first_octet <= 191:
        return "Class B"
    if 192 <= first_octet <= 223:
        return "Class C"
    if 224 <= first_octet <= 239:
        return "Class D (Multicast)"
    if 240 <= first_octet <= 254:
        return "Class E (Experimental)"
    return "Unknown"


def build_interface_single_input(ip_str: str):
    """
    Accepts:
      - IP only:            192.168.1.10     (defaults /32)
      - IP/CIDR:            192.168.1.10/24
      - IPv6:               2001:db8::1 or 2001:db8::1/64
    """
    ip_str = ip_str.strip()
    if "/" in ip_str:
        return ipaddress.ip_interface(ip_str)
    default_prefix = "128" if ":" in ip_str else "32"
    return ipaddress.ip_interface(f"{ip_str}/{default_prefix}")


def analyze_address(ip_str: str) -> dict:
    """Return table fields dict for IPv4/IPv6."""
    try:
        iface = build_interface_single_input(ip_str)
    except Exception as e:
        raise ValueError(f"Invalid IP / Subnet: {e}")

    ip_obj = iface.ip
    net_obj = iface.network

    result = {
        "Valid IP?": "Yes",
        "IP Version": f"IPv{ip_obj.version}",
        "IP Address": str(ip_obj),
        "Network Address": str(net_obj.network_address),
        "Prefix Length": f"/{net_obj.prefixlen}",
        "Total Addresses in Subnet": net_obj.num_addresses,
        "Private Address?": "Yes" if ip_obj.is_private else "No",
        "Globally Routable?": "Yes" if ip_obj.is_global else "No",
    }

    if ip_obj.version == 4:
        # IPv4 details
        broadcast_address = net_obj.broadcast_address
        if net_obj.prefixlen < 31:
            first_usable = ipaddress.IPv4Address(int(net_obj.network_address) + 1)
            last_usable  = ipaddress.IPv4Address(int(broadcast_address) - 1)
            usable_hosts = max(net_obj.num_addresses - 2, 0)
        else:
            first_usable = "N/A"
            last_usable  = "N/A"
            usable_hosts = 0

        wildcard_mask = ipaddress.IPv4Address((~int(net_obj.netmask)) & 0xFFFFFFFF)

        result.update({
            "IP Class": get_ipv4_class(str(ip_obj)),
            "Subnet Mask": str(net_obj.netmask),
            "Wildcard Mask": str(wildcard_mask),
            "Broadcast Address": str(broadcast_address),
            "Starting Range": str(first_usable),
            "Ending Range": str(last_usable),
            "Usable Host Count": usable_hosts,
        })
    else:
        # IPv6: keep IPv4-only fields as N/A (matches your screenshot layout)
        result.update({
            "IP Class": "N/A (IPv6)",
            "Subnet Mask": "N/A (IPv6)",
            "Wildcard Mask": "N/A (IPv6)",
            "Broadcast Address": "N/A (IPv6)",
            "Starting Range": "N/A (IPv6)",
            "Ending Range": "N/A (IPv6)",
            "Usable Host Count": "N/A (IPv6)",
            "Compressed Form": ip_obj.compressed,
            "Full Form": ip_obj.exploded,
        })

    return result


# ---------- Summary line ----------

def generate_summary(result: dict) -> str:
    ip_ver = result.get("IP Version", "?")
    ip_addr = result.get("IP Address", "?")
    prefix  = result.get("Prefix Length", "?")
    net     = result.get("Network Address", "?")

    if ip_ver == "IPv4":
        ip_class = result.get("IP Class", "Unknown")
        priv = "private" if result.get("Private Address?") == "Yes" else "public"
        hosts = result.get("Usable Host Count", "N/A")
        first_u = result.get("Starting Range", "N/A")
        last_u  = result.get("Ending Range", "N/A")
        return (f"{ip_addr} is a {priv} {ip_class} IPv4 address. "
                f"Subnet {net}{prefix} has {hosts} usable hosts "
                f"(from {first_u} to {last_u}).")
    else:
        priv = "private/local" if result.get("Private Address?") == "Yes" else "global"
        return (f"{ip_addr} is an {priv} IPv6 address with prefix {prefix} "
                f"in network {net}{prefix}.")


# ---------- Clipboard ----------

def copy_results_to_clipboard(root: tk.Tk, tree: ttk.Treeview):
    rows = tree.get_children()
    if not rows:
        messagebox.showwarning("Nothing to copy", "No results to copy yet.")
        return
    lines = []
    for row_id in rows:
        key, val = tree.item(row_id, "values")
        lines.append(f"{key}: {val}")
    blob = "\n".join(lines)
    try:
        root.clipboard_clear()
        root.clipboard_append(blob)
        root.update()
        messagebox.showinfo("Copied", "Results copied to clipboard.")
    except Exception as e:
        messagebox.showerror("Copy Failed", f"Could not copy results:\n{e}")


# ---------- Live status ----------

def live_validate(ip_entry: tk.Entry, status_label: ttk.Label):
    txt = ip_entry.get().strip()
    if not txt:
        status_label.config(text="Please enter an IP address", foreground="#b71c1c")
        return
    try:
        _ = build_interface_single_input(txt)
        status_label.config(text="Validation successful", foreground="#1b5e20")
    except Exception:
        status_label.config(text="Invalid / incomplete ❌", foreground="#b71c1c")


# ---------- Validate button ----------

def run_validation(ip_entry: tk.Entry,
                   tree: ttk.Treeview,
                   status_label: ttk.Label,
                   summary_label: tk.Label):
    ip_in = ip_entry.get().strip()
    if not ip_in:
        messagebox.showerror("Error", "Please enter an IP address.")
        status_label.config(text="No IP entered", foreground="#b71c1c")
        summary_label.config(text="")
        return
    try:
        result = analyze_address(ip_in)
    except ValueError as err:
        for row in tree.get_children():
            tree.delete(row)
        messagebox.showerror("Invalid Input", str(err))
        status_label.config(text="Invalid IP / Subnet", foreground="#b71c1c")
        summary_label.config(text="")
        return

    # refresh table
    for row in tree.get_children():
        tree.delete(row)
    for k, v in result.items():
        tree.insert("", "end", values=(k, v))
    apply_row_colors(tree)

    status_label.config(text="Validation successful", foreground="#1b5e20")
    summary_label.config(text=generate_summary(result), foreground="black")


def apply_row_colors(tree: ttk.Treeview):
    tree.tag_configure("evenrow", background="#e3f2fd")
    tree.tag_configure("oddrow",  background="#fffde7")
    for i, item in enumerate(tree.get_children()):
        tree.item(item, tags=("evenrow" if i % 2 == 0 else "oddrow",))


# ---------- GUI ----------

def build_gui():
    root = tk.Tk()
    root.title("IP Class and Subnet Calculator")
    root.geometry("1000x760")
    root.configure(bg="#d9d9d9")
    root.minsize(700, 550)

    # Header
    header = tk.Frame(root, bg="#1565c0")
    header.pack(fill="x")
    tk.Label(header, text="IP Class and Subnet Calculator",
             bg="#1565c0", fg="white", font=("Segoe UI", 15, "bold"),
             pady=10).pack(fill="x")

    main = tk.Frame(root, bg="#d9d9d9")
    main.pack(fill="both", expand=True)

    # Input card
    card = ttk.Frame(main, padding=15)
    card.pack(fill="x", padx=20, pady=15)

    form = ttk.Frame(card)
    form.pack(anchor="center")

    ttk.Label(form, text="IP Address (IPv4 or IPv6):", font=("Segoe UI", 11, "bold"))\
        .grid(row=0, column=0, sticky="e", pady=5, padx=(0, 10))

    ip_entry = tk.Entry(form, width=40, font=("Consolas", 11),
                        bg="white", fg="black", insertbackground="black")
    ip_entry.grid(row=0, column=1, pady=5, sticky="w")

    status_label = ttk.Label(form, text="", font=("Segoe UI", 10, "italic"))
    status_label.grid(row=1, column=0, columnspan=2, pady=(5, 0), sticky="n")

    ip_entry.bind("<KeyRelease>", lambda e: live_validate(ip_entry, status_label))

    validate_btn = tk.Button(form, text="Validate", bg="#42a5f5", fg="black",
                             activebackground="#1e88e5", activeforeground="black",
                             font=("Segoe UI", 12, "bold"), relief="raised", bd=4, width=20,
                             command=lambda: run_validation(ip_entry, tree, status_label, summary_label))
    validate_btn.grid(row=2, column=0, columnspan=2, pady=12, sticky="n")

    # Summary
    summary_card = tk.LabelFrame(main, text="Summary", bg="#d9d9d9", fg="black",
                                 font=("Segoe UI", 10, "bold"), padx=10, pady=10, labelanchor="nw")
    summary_card.pack(fill="x", padx=20, pady=(0, 10))

    summary_label = tk.Label(summary_card, text="", bg="#d9d9d9", fg="black",
                             font=("Segoe UI", 10), justify="left", wraplength=900, anchor="w")
    summary_label.pack(fill="x")

    # Table
    table_card = ttk.Frame(main, padding=10)
    table_card.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview.Heading", background="#1565c0", foreground="black", font=("Segoe UI", 10, "bold"))
    style.configure("Treeview", rowheight=26, font=("Consolas", 10))
    style.map("Treeview", background=[("selected", "#64b5f6")])

    columns = ("Property", "Value")
    tree = ttk.Treeview(table_card, columns=columns, show="headings", height=12)
    tree.heading("Property", text="Property")
    tree.heading("Value", text="Value")
    tree.column("Property", width=260, anchor="w")
    tree.column("Value", width=520, anchor="w")
    tree.grid(row=0, column=0, sticky="nsew")

    scrollbar = ttk.Scrollbar(table_card, orient="vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.grid(row=0, column=1, sticky="ns")

    copy_btn = tk.Button(table_card, text="Copy Results", bg="#42a5f5", fg="black",
                         activebackground="#1e88e5", activeforeground="black",
                         font=("Segoe UI", 10, "bold"), relief="raised", bd=3, width=16,
                         command=lambda: copy_results_to_clipboard(root, tree))
    copy_btn.grid(row=1, column=0, sticky="w", pady=(10, 0))

    table_card.grid_rowconfigure(0, weight=1)
    table_card.grid_columnconfigure(0, weight=1)

    root.mainloop()


if __name__ == "__main__":
    build_gui()

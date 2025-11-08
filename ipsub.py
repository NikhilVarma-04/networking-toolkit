import tkinter as tk
from tkinter import messagebox
import ipaddress

# Global theme state
is_dark_mode = False

def validate_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return True, ip_obj
    except ValueError:
        return False, None

def get_ipv4_type(ip_obj):
    if ip_obj.is_loopback:
        return "Loopback"
    elif ip_obj.is_private:
        return "Private"
    elif ip_obj.is_link_local:
        return "Link-Local"
    elif ip_obj.is_multicast:
        return "Multicast"
    elif str(ip_obj) == "255.255.255.255":
        return "Broadcast"
    elif ip_obj.is_reserved:
        return "Reserved"
    else:
        return "Public"

def get_ipv6_type(ip_obj):
    if ip_obj == ipaddress.IPv6Address("::"):
        return "Unspecified"
    elif ip_obj == ipaddress.IPv6Address("::1"):
        return "Loopback"
    elif ip_obj.is_multicast:
        return "Multicast"
    elif ip_obj.is_link_local:
        return "Link-Local"
    elif ip_obj.is_private:
        return "Unique Local"
    elif ip_obj.is_global:
        return "Global Unicast"
    else:
        return "Unknown"

def get_class_details(ip_obj):
    if isinstance(ip_obj, ipaddress.IPv4Address):
        first_octet = int(str(ip_obj).split('.')[0])
        if 0 <= first_octet <= 127:
            return 'A', '0 – 127', '0.0.0.0', '126.255.255.255', 8
        elif 128 <= first_octet <= 191:
            return 'B', '128 – 191', '128.0.0.0', '191.255.255.255', 16
        elif 192 <= first_octet <= 223:
            return 'C', '192 – 223', '192.0.0.0', '223.255.255.255', 24
        elif 224 <= first_octet <= 239:
            return 'D (Multicast)', '224 – 239', '224.0.0.0', '239.255.255.255', None
        elif 240 <= first_octet <= 255:
            return 'E (Experimental)', '240 – 255', '240.0.0.0', '255.255.255.255', None
    return 'N/A', 'N/A', 'N/A', 'N/A', None

def get_host_range(ip_obj, prefix):
    if prefix is None:
        return "N/A", "N/A", "N/A", "N/A"
    net = ipaddress.IPv4Network(f"{ip_obj}/{prefix}", strict=False)
    hosts = list(net.hosts())
    if len(hosts) >= 2:
        return str(net.network_address), str(net.broadcast_address), str(hosts[0]), str(hosts[-1])
    else:
        return str(net.network_address), str(net.broadcast_address), "N/A", "N/A"

def get_ipv6_subnet_bounds(ip_str):
    try:
        net = ipaddress.IPv6Network(ip_str, strict=False)
        return str(net.network_address), str(net[-1])
    except Exception:
        return "N/A", "N/A"

def calculate_ip():
    ip = ip_entry.get().strip()
    ip_base = ip.split('/')[0]
    valid, ip_obj = validate_ip(ip_base)
    if not valid:
        messagebox.showerror("Invalid IP", "Please enter a valid IPv4 or IPv6 address.")
        for var in [type_val, class_val, octet_val, start_val, end_val, net_val, bc_val, first_val, last_val]:
            var.set("")
        return

    if isinstance(ip_obj, ipaddress.IPv4Address):
        ip_type = f"IPv4 – {get_ipv4_type(ip_obj)}"
        ip_class, octet_range, start_range, end_range, prefix = get_class_details(ip_obj)
        class_val.set(ip_class)
        octet_val.set(octet_range)
        start_val.set(start_range)
        end_val.set(end_range)
        if prefix:
            net, bc, first, last = get_host_range(ip_obj, prefix)
            net_val.set(net)
            bc_val.set(bc)
            first_val.set(first)
            last_val.set(last)
        else:
            net_val.set("N/A")
            bc_val.set("N/A")
            first_val.set("N/A")
            last_val.set("N/A")
    else:
        ip_type = f"IPv6 – {get_ipv6_type(ip_obj)}"
        class_val.set("N/A")
        octet_val.set("N/A")
        start, end = get_ipv6_subnet_bounds(ip)
        start_val.set(start)
        end_val.set(end)
        net_val.set(start)
        bc_val.set("N/A")
        first_val.set("N/A")
        last_val.set("N/A")

    type_val.set(ip_type)

def toggle_theme():
    global is_dark_mode
    is_dark_mode = not is_dark_mode
    bg = "#1a1a2e" if is_dark_mode else "#f0f8ff"
    fg = "#ffffff" if is_dark_mode else "#000000"
    root.configure(bg=bg)
    for frame in [input_frame, output_frame]:
        frame.configure(bg=bg)
        # LabelFrame title color:
        frame.configure(fg="#00ffff")
        for child in frame.winfo_children():
            try:
                child.configure(bg=bg, fg=fg)
                if isinstance(child, tk.Entry):
                    child.configure(bg="#fff8dc" if not is_dark_mode else "#232842",
                                    fg="#000080" if not is_dark_mode else "#e9f1ff",
                                    insertbackground="#000080" if not is_dark_mode else "#e9f1ff")
            except tk.TclError:
                pass
    theme_btn.configure(text="🌞 Light Mode" if is_dark_mode else "🌙 Dark Mode",
                        bg="#444" if is_dark_mode else "#4682b4", fg="white")

# GUI setup
root = tk.Tk()
root.title("🧰 Networking Toolkit")
root.geometry("720x800")
root.configure(bg="#1a1a2e")

label_font = ("Segoe UI", 12, "bold")   # <-- use this name
value_font = ("Consolas", 12)

# Input Section
input_frame = tk.LabelFrame(root, text="🔎 IP Address Input", font=label_font, bg="#1a1a2e", fg="#00ffff", padx=10, pady=10)
input_frame.pack(pady=15, padx=20, fill="x")

tk.Label(input_frame, text="Enter IP Address (IPv4 or IPv6):", font=label_font, bg="#1a1a2e", fg="#00ffff").pack(anchor="w")
ip_entry = tk.Entry(input_frame, width=30, font=value_font, bg="#fff8dc", fg="#000080", bd=2, relief="groove")
ip_entry.pack(pady=5)

tk.Button(input_frame, text="Calculate", font=label_font, bg="#4682b4", fg="white", command=calculate_ip).pack(pady=10)

# Output Section
output_frame = tk.LabelFrame(root, text="📊 IP Analysis Result", font=label_font, bg="#1a1a2e", fg="#00ffff", padx=10, pady=10)
output_frame.pack(pady=10, padx=20, fill="x")

type_val   = tk.StringVar()
class_val  = tk.StringVar()
octet_val  = tk.StringVar()
start_val  = tk.StringVar()
end_val    = tk.StringVar()
net_val    = tk.StringVar()
bc_val     = tk.StringVar()
first_val  = tk.StringVar()
last_val   = tk.StringVar()

def labeled_row(parent, label, var, color):
    frame = tk.Frame(parent, bg=parent["bg"])
    frame.pack(anchor="w", pady=3)
    tk.Label(frame, text=label, font=label_font, bg=parent["bg"], fg="#00ffff").pack(side="left")
    tk.Label(frame, textvariable=var, font=value_font, bg=parent["bg"], fg=color).pack(side="left")

labeled_row(output_frame, "🌐 Type               :", type_val, "#00bfff")
labeled_row(output_frame, "📦 Class              :", class_val, "#7fff00")
labeled_row(output_frame, "🔢 First Octet Range  :", octet_val, "#ff69b4")
labeled_row(output_frame, "📍 Subnet Start       :", start_val, "#00fa9a")
labeled_row(output_frame, "📍 Subnet End         :", end_val, "#ff4500")
labeled_row(output_frame, "🌐 Network Address    :", net_val, "#1e90ff")
labeled_row(output_frame, "📡 Broadcast Address  :", bc_val, "#ffa500")
labeled_row(output_frame, "🧍 First Host         :", first_val, "#20b2aa")
labeled_row(output_frame, "🚪 Last Host          :", last_val, "#dc143c")

# Theme toggle button  (FIX: use label_font instead of 'label')
theme_btn = tk.Button(root, text="🌙 Dark Mode", font=label_font, bg="#4682b4", fg="white", command=toggle_theme)
theme_btn.pack(pady=10)

root.mainloop()

import tkinter as tk
from tkinter import messagebox
import ipaddress

# Global theme state
is_dark_mode = False

# -----------------------
# Validation & parsing
# -----------------------
def validate_ip(ip):
    """
    Accepts either:
      - plain IP:  192.168.1.10
      - IP/CIDR:   192.168.1.10/24, 2001:db8::1/64
    Returns: (ok, ip_obj, user_prefix)
      ip_obj: ipaddress.IPv4Address or IPv6Address
      user_prefix: int or None
    """
    ip = ip.strip()
    try:
        if "/" in ip:
            iface = ipaddress.ip_interface(ip)
            return True, iface.ip, iface.network.prefixlen
        else:
            return True, ipaddress.ip_address(ip), None
    except ValueError:
        return False, None, None

# -----------------------
# IPv4 class info
# -----------------------
def get_class_details(ip_obj):
    """
    Returns (class_label, first_octet_range, class_start, class_end, class_default_prefix)
    For IPv6: ('N/A','N/A','N/A','N/A', None)
    """
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
        else:
            return 'Invalid Class', 'N/A', None, None, None
    else:
        # IPv6: no classful addressing
        return 'N/A', 'N/A', 'N/A', 'N/A', None

# -----------------------
# Host range for IPv4
# -----------------------
def get_host_range(ip_obj, prefix):
    """
    For IPv4 only. Returns (network, broadcast, first_host, last_host).
    Uses traditional behavior: /31 and /32 → no usable host range.
    """
    if prefix is None:
        return "N/A", "N/A", "N/A", "N/A"
    net = ipaddress.IPv4Network(f"{ip_obj}/{prefix}", strict=False)
    hosts = list(net.hosts())
    if len(hosts) >= 2:
        return str(net.network_address), str(net.broadcast_address), str(hosts[0]), str(hosts[-1])
    else:
        # /31 or /32 traditional behavior: no usable hosts
        return str(net.network_address), str(net.broadcast_address), "N/A", "N/A"

# -----------------------
# Button handler
# -----------------------
def calculate_ip():
    ip = ip_entry.get().strip()
    valid, ip_obj, user_prefix = validate_ip(ip)
    if not valid:
        messagebox.showerror("Invalid IP", "Enter a valid IP or IP/CIDR (e.g., 192.168.1.10 or 192.168.1.10/24).")
        for var in [type_val, class_val, octet_val, start_val, end_val, net_val, bc_val, first_val, last_val]:
            var.set("")
        return

    ip_type = "IPv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "IPv6"
    ip_class, octet_range, start_range, end_range, class_default_prefix = get_class_details(ip_obj)

    # Set common fields
    type_val.set(ip_type)
    class_val.set(ip_class)
    octet_val.set(octet_range)
    start_val.set(start_range)
    end_val.set(end_range)

    if ip_type == "IPv4":
        # Prefix choice: user-supplied prefix > class default (A/B/C)
        prefix = user_prefix if user_prefix is not None else class_default_prefix
        if prefix is not None:
            net, bc, first, last = get_host_range(ip_obj, prefix)
            net_val.set(net)
            bc_val.set(bc)
            first_val.set(first)
            last_val.set(last)
        else:
            # Classes D/E (or invalid class): no traditional host range
            net_val.set("N/A")
            bc_val.set("N/A")
            first_val.set("N/A")
            last_val.set("N/A")
    else:
        # IPv6: v4-specific concepts are N/A
        net_val.set("N/A")
        bc_val.set("N/A")
        first_val.set("N/A")
        last_val.set("N/A")

# -----------------------
# Theme toggling helpers
# -----------------------
def _safe_set_colors(widget, bg=None, fg=None):
    try:
        if bg is not None:
            widget.configure(bg=bg)
        if fg is not None and hasattr(widget, "cget") and "fg" in widget.keys():
            widget.configure(fg=fg)
    except Exception:
        pass

def _walk_children(widget, bg=None, fg=None):
    _safe_set_colors(widget, bg, fg)
    for child in widget.winfo_children():
        _walk_children(child, bg, fg)

def toggle_theme():
    global is_dark_mode
    is_dark_mode = not is_dark_mode
    bg = "#1a1a2e" if is_dark_mode else "#f0f8ff"
    text_color = "#ffffff" if is_dark_mode else "#000000"

    _walk_children(root, bg=bg, fg=text_color)

    # restore accent color for section titles
    try:
        input_frame.configure(fg="#00ffff")
        output_frame.configure(fg="#00ffff")
        reference_frame.configure(fg="#00ffff")
    except Exception:
        pass

    theme_btn.configure(
        text="🌞 Light Mode" if is_dark_mode else "🌙 Dark Mode",
        bg="#444" if is_dark_mode else "#4682b4",
        fg="white"
    )

# -----------------------
# GUI setup
# -----------------------
root = tk.Tk()
root.title("🧰 Networking Toolkit")
root.geometry("720x820")
root.configure(bg="#1a1a2e")

label_font = ("Segoe UI", 12, "bold")
value_font = ("Consolas", 12)

# Input Section
input_frame = tk.LabelFrame(root, text="🔎 IP Address Input", font=label_font,
                            bg="#1a1a2e", fg="#00ffff", padx=10, pady=10)
input_frame.pack(pady=15, padx=20, fill="x")

tk.Label(input_frame,
         text="Enter IP Address (IPv4/IPv6 or CIDR):",
         font=label_font, bg="#1a1a2e", fg="#00ffff").pack(anchor="w")

ip_entry = tk.Entry(input_frame, width=34, font=value_font,
                    bg="#fff8dc", fg="#000080", bd=2, relief="groove")
ip_entry.pack(pady=5)

tk.Button(input_frame, text="Calculate", font=label_font,
          bg="#4682b4", fg="white", command=calculate_ip).pack(pady=10)

# Output Section
output_frame = tk.LabelFrame(root, text="📊 IP Analysis Result", font=label_font,
                             bg="#1a1a2e", fg="#00ffff", padx=10, pady=10)
output_frame.pack(pady=10, padx=20, fill="x")

type_val = tk.StringVar()
class_val = tk.StringVar()
octet_val = tk.StringVar()
start_val = tk.StringVar()
end_val = tk.StringVar()
net_val = tk.StringVar()
bc_val = tk.StringVar()
first_val = tk.StringVar()
last_val = tk.StringVar()

def labeled_row(parent, label, var, color):
    frame = tk.Frame(parent, bg=parent["bg"])
    frame.pack(anchor="w", pady=3)
    tk.Label(frame, text=label, font=label_font, bg=parent["bg"], fg="#00ffff").pack(side="left")
    tk.Label(frame, textvariable=var, font=value_font, bg=parent["bg"], fg=color).pack(side="left")

labeled_row(output_frame, "🌐 Type               :", type_val,  "#00bfff")
labeled_row(output_frame, "📦 Class              :", class_val, "#7fff00")
labeled_row(output_frame, "🔢 First Octet Range  :", octet_val, "#ff69b4")
labeled_row(output_frame, "📍 Subnet Start       :", start_val,  "#00fa9a")
labeled_row(output_frame, "📍 Subnet End         :", end_val,    "#ff4500")
labeled_row(output_frame, "🌐 Network Address    :", net_val,    "#1e90ff")
labeled_row(output_frame, "📡 Broadcast Address  :", bc_val,     "#ffa500")
labeled_row(output_frame, "🧍 First Host         :", first_val,  "#20b2aa")
labeled_row(output_frame, "🚪 Last Host          :", last_val,   "#dc143c")

# Theme toggle button
theme_btn = tk.Button(root, text="🌙 Dark Mode", font=label_font,
                      bg="#4682b4", fg="white", command=toggle_theme)
theme_btn.pack(pady=10)

# Reference Box
table_text = (
    "IPv4 Class Reference\n"
    "--------------------\n"
    "Class A: 0–127    | Default mask /8   | Example: 10.0.0.0/8\n"
    "Class B: 128–191  | Default mask /16  | Example: 172.16.0.0/16\n"
    "Class C: 192–223  | Default mask /24  | Example: 192.168.0.0/24\n"
    "Class D: 224–239  | Multicast         | Example: 224.0.0.0\n"
    "Class E: 240–255  | Experimental      | Example: 240.0.0.0\n"
)

reference_frame = tk.LabelFrame(root, text="Reference", font=label_font,
                                bg=root["bg"], fg="#00ffff", padx=10, pady=10)
reference_frame.pack(pady=10, padx=20, fill="x")

reference_label = tk.Label(reference_frame, text=table_text, font=("Courier New", 10),
                           bg=root["bg"], fg="#ffffff", justify="left", anchor="w")
reference_label.pack(padx=10, pady=10)

root.mainloop()

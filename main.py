import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, get_if_list, conf
import threading


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sniff嗅探器")
        self.root.geometry("1600x720+100+100")

        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.sniffer_thread = None
        self.sniffing = False
        self.packets = []

        self.setup_ui()

    def setup_ui(self):
        self.interfaces = get_if_list()
        if_dicts = conf.ifaces
        self.interface_names = [if_dicts.data[key].description for key in self.interfaces]

        control_frame = ttk.Frame(self.root, padding="10 10 10 10")
        control_frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(control_frame, text="选择网络接口:").pack(side=tk.LEFT, padx=5)
        self.interface_combo = ttk.Combobox(control_frame, values=self.interface_names, state="readonly", width=40)
        if self.interface_names:
            self.interface_combo.set(self.interface_names[0])
        self.interface_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(control_frame, text="选择协议过滤器:").pack(side=tk.LEFT, padx=5)
        self.protocol_combo = ttk.Combobox(control_frame, values=[
            "全部", "tcp", "udp", "icmp", "arp", "http", "https", "dns", "ftp", "ssh"
        ], state="readonly")
        self.protocol_combo.current(0)
        self.protocol_combo.pack(side=tk.LEFT, padx=5)

        self.start_button = ttk.Button(control_frame, text="开始嗅探", command=self.on_start_sniff)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="停止嗅探", command=self.on_stop_sniff)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(control_frame, text="清屏", command=self.clear_display)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.tcp_stream_button = ttk.Button(control_frame, text="追踪TCP流", command=self.on_tcp_stream)
        self.tcp_stream_button.pack(side=tk.LEFT, padx=5)

        # 添加筛选按钮
        self.filter_button = ttk.Button(control_frame, text="筛选", command=self.filter_packets)
        self.filter_button.pack(side=tk.LEFT, padx=5)

        packet_frame = ttk.Frame(self.root, padding="5")
        packet_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(packet_frame, text="捕获数据包列表:").pack(anchor="w", pady=5)
        columns = ("index", "ip_version", "protocol", "src", "dst")
        self.packet_treeview = ttk.Treeview(packet_frame, columns=columns, show="headings")
        self.packet_treeview.heading("index", text="序号")
        self.packet_treeview.heading("ip_version", text="IP版本")
        self.packet_treeview.heading("protocol", text="传输层协议")
        self.packet_treeview.heading("src", text="源地址")
        self.packet_treeview.heading("dst", text="目标地址")

        self.packet_treeview.column("index", width=50, anchor=tk.CENTER)
        self.packet_treeview.column("ip_version", width=80, anchor=tk.CENTER)
        self.packet_treeview.column("protocol", width=100, anchor=tk.CENTER)
        self.packet_treeview.column("src", width=200, anchor=tk.W)
        self.packet_treeview.column("dst", width=200, anchor=tk.W)

        self.packet_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.packet_treeview.bind('<<TreeviewSelect>>', self.on_packet_select)

        scrollbar = ttk.Scrollbar(packet_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_treeview.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.packet_treeview.yview)

        detail_frame = ttk.Frame(self.root, padding="5")
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        ttk.Label(detail_frame, text="帧解析:").pack(anchor="w", pady=5)
        self.detail_text = tk.Text(detail_frame, height=20)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(detail_frame, text="原始MAC帧流:").pack(anchor="w", pady=5)
        self.stream_text = tk.Text(detail_frame, height=20)
        self.stream_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # 清理
    def clear_display(self):
        for i in self.packet_treeview.get_children():
            self.packet_treeview.delete(i)
        self.detail_text.delete('1.0', tk.END)
        self.stream_text.delete('1.0', tk.END)
        self.packets.clear()

    # 筛选功能
    def filter_packets(self):
        protocol_filter = self.protocol_combo.get().lower()
        filtered_packets = []

        if protocol_filter == "全部":
            filtered_packets = self.packets
        else:
            for packet in self.packets:
                if packet.payload.name.lower() == "ip" or packet.payload.name.lower() == "ipv6":
                    if packet.payload.payload.name.lower() == protocol_filter:
                        filtered_packets.append(packet)
                elif packet.payload.name.lower() == protocol_filter:
                    filtered_packets.append(packet)

        self.clear_display()

        for packet in filtered_packets:
            self.packet_callback(packet)

    def packet_callback(self, packet):
        # TODO: 目前定位问题在这，报错WARNING: Socket <scapy.arch.libpcap.L2pcapListenSocket object at 0x0000000007F70D80> failed with 'src'. It was closed.
        print(packet.summary())
        # self.packets.append(packet)
        # index = len(self.packets)
        #
        # ip_version = "/"
        # protocol = "/"
        # src = "/"
        # dst = "/"
        #
        # if packet.payload.name == "IP":
        #     ip_version = "IPv4"
        #     src = packet.payload.src
        #     dst = packet.payload.dst
        #     if packet.payload.payload.name == "TCP":
        #         protocol = "TCP"
        #     elif packet.payload.payload.name == "UDP":
        #         protocol = "UDP"
        # elif packet.payload.name == "IPv6":
        #     ip_version = "IPv6"
        #     src = packet.payload.src
        #     dst = packet.payload.dst
        #     if packet.payload.payload.name == "TCP":
        #         protocol = "TCP"
        #     elif packet.payload.payload.name == "UDP":
        #         protocol = "UDP"
        # elif packet.payload.name == "ARP":
        #     ip_version = "ARP"
        #     src = packet.payload.src
        #     dst = packet.payload.dst
        #     if packet.payload.payload.name == "TCP":
        #         protocol = "TCP"
        #     elif packet.payload.payload.name == "UDP":
        #         protocol = "UDP"
        # elif packet.payload.name == "LLC":
        #     ip_version = "LLC"
        #     src = packet.payload.src
        #     dst = packet.payload.dst
        #     if packet.payload.payload.name == "TCP":
        #         protocol = "TCP"
        #     elif packet.payload.payload.name == "UDP":
        #         protocol = "UDP"
        #
        # self.packet_treeview.insert("", tk.END, values=(index, ip_version, protocol, src, dst))

    def start_sniffer(self, interface, protocol_filter):
        self.sniffing = True
        filter_str = protocol_filter.lower()

        # 特定协议需要使用常用端口进行过滤
        if protocol_filter == "http":
            filter_str = "tcp port 80"
        elif protocol_filter == "https":
            filter_str = "tcp port 443"
        elif protocol_filter == "dns":
            filter_str = "udp port 53"
        elif protocol_filter == "ftp":
            filter_str = "tcp port 21"
        elif protocol_filter == "ssh":
            filter_str = "tcp port 22"
        elif protocol_filter == "全部":
            filter_str = ""

        print(f"开始监听 {interface} 接口上的数据包，协议过滤器: {filter_str}...")
        try:
            sniff(iface=interface, filter=filter_str, prn=self.packet_callback,
                  stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            print(f"嗅探时出错: {e}")

    def on_start_sniff(self):
        if not self.sniffing:
            interface = self.interfaces[self.interface_combo.current()]
            protocol = self.protocol_combo.get()

            if interface:
                self.sniffing = True
                self.sniffer_thread = threading.Thread(target=self.start_sniffer, args=(interface, protocol))
                self.sniffer_thread.daemon = True
                self.sniffer_thread.start()
            else:
                print("请选择一个网络接口！")

    def on_stop_sniff(self):
        self.sniffing = False
        print("嗅探已停止")

    def on_packet_select(self, event):
        selected_items = self.packet_treeview.selection()
        if not selected_items:
            return
        index = int(self.packet_treeview.item(selected_items[0])["values"][0]) - 1
        packet = self.packets[index]

        self.detail_text.delete('1.0', tk.END)
        parse = str(packet.show(dump=True))
        self.detail_text.insert(tk.END, parse)

        self.stream_text.delete('1.0', tk.END)
        hex_data = ' '.join(f"{byte:02x}" for byte in bytes(packet))
        self.stream_text.insert(tk.END, hex_data)

    def get_tcp_stream(self, packet):
        stream = []
        if packet.payload.payload.name == "TCP":
            for p in self.packets:
                temp = p.payload.dst
                if packet.payload.payload.name == "TCP" and (
                        (p.payload.src == packet.payload.src and p.payload.dst == packet.payload.dst and
                         p.payload.payload.sport == packet.payload.payload.sport and p.payload.payload.dport == packet.payload.payload.dport) or
                        (p.payload.src == packet.payload.dst and p.payload.dst == packet.payload.src and
                         p.payload.payload.sport == packet.payload.payload.dport and p.payload.payload.dport == packet.payload.payload.sport)
                ):
                    stream.append(p)
        return stream

    def on_tcp_stream(self):
        selected_items = self.packet_treeview.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择一个TCP数据包！")
            return
        index = int(self.packet_treeview.item(selected_items[0])["values"][0]) - 1
        packet = self.packets[index]

        tcp_stream = self.get_tcp_stream(packet)
        new_window = tk.Toplevel(self.root)
        new_window.title("TCP流追踪")

        # 设置窗口尺寸，这里设置为800x400可以自己调整
        new_window.geometry("800x400")

        text = tk.Text(new_window, wrap=tk.NONE)  # wrap=tk.NONE 表示不自动换行
        text.pack(fill=tk.BOTH, expand=True)

        scrollbar_y = ttk.Scrollbar(new_window, orient=tk.VERTICAL, command=text.yview)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x = ttk.Scrollbar(new_window, orient=tk.HORIZONTAL, command=text.xview)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

        text.config(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        for p in tcp_stream:
            text.insert(tk.END, f"{p.summary()}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

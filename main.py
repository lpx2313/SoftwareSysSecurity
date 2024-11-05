import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, get_if_list, conf
import threading
import ipaddress

class PacketSnifferApp:
    def __init__(self, root):
        """
        初始化应用程序
        :param root: tk主界面根节点
        """
        self.root = root
        self.root.title("刘鹏翔的Sniff嗅探器")
        self.root.geometry("1200x720+100+100")  # 窗口大小
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.sniffer_thread = None
        self.sniffing = False
        self.packets = []
        self.filtered_packets = []
        self.setup_ui()

    def setup_ui(self):
        """
        初始化GUI界面配置
        :return: None
        """
        # 获取当前主机所有网卡信息
        self.interfaces = get_if_list()
        self.if_dicts = conf.ifaces
        self.interface_names = [self.if_dicts.data[key].description for key in self.interfaces]
        self.interface_names.insert(0, "全部")

        control_frame = ttk.Frame(self.root, padding="10 10 10 10")
        control_frame.pack(side=tk.TOP, fill=tk.X)

        # GUI构建下拉框供用户选择嗅探的网卡
        ttk.Label(control_frame, text="请选择要嗅探的网络接口:").pack(side=tk.LEFT, padx=5)
        self.interface_combo = ttk.Combobox(control_frame, values=self.interface_names, state="readonly", width=40)
        if self.interface_names:
            self.interface_combo.set(self.interface_names[0])
        self.interface_combo.pack(side=tk.LEFT, padx=5)

        # GUI构建下拉框供用户选择协议过滤
        protocol_frame = ttk.Frame(control_frame)
        protocol_frame.pack(side=tk.LEFT, padx=5)

        ttk.Label(control_frame, text="选择协议过滤器{应用层/传输层}:").pack(side=tk.LEFT, padx=5)
        self.protocol_combo = ttk.Combobox(control_frame, values=[
            "全部", "All/tcp", "http/tcp", "https/tcp", "ftp/tcp", "ssh/tcp", "All/udp", "dns/udp"],
                                           state="readonly", width=10)
        self.protocol_combo.current(0)
        self.protocol_combo.pack(side=tk.LEFT, padx=5)

        # GUI开始嗅探按钮
        self.start_button = ttk.Button(control_frame, text="开始嗅探", command=self.on_start_sniff)
        self.start_button.pack(side=tk.LEFT, padx=5)

        # GUI停止嗅探按钮
        self.stop_button = ttk.Button(control_frame, text="停止嗅探", command=self.on_stop_sniff, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # GUI清屏按钮
        self.clear_button = ttk.Button(control_frame, text="清屏", command=self.clear_display)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # GUI追踪TCP流按钮
        self.tcp_stream_button = ttk.Button(control_frame, text="追踪TCP流", command=self.on_tcp_stream)
        self.tcp_stream_button.pack(side=tk.LEFT, padx=5)

        # GUI展示当前捕获数据包
        packet_frame = ttk.Frame(self.root, padding="5")
        packet_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        label_frame = ttk.Frame(packet_frame)
        label_frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(label_frame, text="捕获数据包列表(输入合法host地址筛选):").pack(side=tk.LEFT, anchor="w", pady=5)

        # host输入框和筛选按钮
        self.host_entry = ttk.Entry(label_frame, width=26)
        self.host_entry.pack(side=tk.LEFT, padx=(10, 5))

        self.filter_button = ttk.Button(label_frame, text="筛选", command=self.filter_packets, state="disabled")
        self.filter_button.pack(side=tk.LEFT, padx=(5, 0))

        self.reset_button = ttk.Button(label_frame, text="重置", command=self.reset_filter_packets, state="disabled")
        self.reset_button.pack(side=tk.LEFT, padx=(5, 0))

        columns = ("index", "ip_version", "protocol", "src", "dst")
        self.packet_treeview = ttk.Treeview(packet_frame, columns=columns, show="headings")
        self.packet_treeview.heading("index", text="序号")
        self.packet_treeview.heading("ip_version", text="IP版本")
        self.packet_treeview.heading("protocol", text="传输层协议")
        self.packet_treeview.heading("src", text="源地址")
        self.packet_treeview.heading("dst", text="目标地址")
        self.packet_treeview.column("index", width=50, anchor=tk.CENTER)
        self.packet_treeview.column("ip_version", width=60, anchor=tk.CENTER)
        self.packet_treeview.column("protocol", width=80, anchor=tk.CENTER)
        self.packet_treeview.column("src", width=220, anchor=tk.W)
        self.packet_treeview.column("dst", width=220, anchor=tk.W)
        self.packet_treeview.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.packet_treeview.bind('<<TreeviewSelect>>', self.on_packet_select)

        scrollbar = ttk.Scrollbar(packet_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_treeview.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.packet_treeview.yview)

        detail_frame = ttk.Frame(self.root, padding="5")
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # GUI展示用户选中数据包的MAC帧解析
        ttk.Label(detail_frame, text="帧解析:").pack(anchor="w", pady=5)
        self.detail_text = tk.Text(detail_frame, height=20)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # GUI展示用户选中数据包的原始MAC帧流
        ttk.Label(detail_frame, text="原始MAC帧流:").pack(anchor="w", pady=5)
        self.stream_text = tk.Text(detail_frame, height=20)
        self.stream_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def reset_filter_packets(self):
        """
        重置筛选内容
        :return:
        """
        self.filtered_packets = self.packets.copy()
        self.packet_callback_filter(self.filtered_packets)

    def filter_packets(self):
        """
        根据用户输入筛选host
        :return:
        """
        self.filtered_packets.clear()
        host_filter = self.host_entry.get().strip()

        if host_filter == "":
            self.filtered_packets = self.packets.copy()
            for item in self.packet_treeview.get_children():
                self.packet_treeview.delete(item)
            self.packet_callback_filter(self.filtered_packets)

        elif self.is_valid_ip(host_filter):
            print(f"Filtering packets with valid host: {host_filter}")

            # 清空Treeview中的当前内容
            for item in self.packet_treeview.get_children():
                self.packet_treeview.delete(item)

            # 过滤并显示符合条件的数据包
            for pkt in self.packets:
                if pkt.payload.src == host_filter or pkt.payload.dst == host_filter:
                    self.filtered_packets.append(pkt)

            self.packet_callback_filter(self.filtered_packets)
        else:
            messagebox.showwarning("无效IP地址", f"输入的地址 '{host_filter}' 不是合法的 IPv4 或 IPv6 地址。")

    def is_valid_ip(self, address):
        """
        检查给定的地址是否是有效的IPv4或IPv6地址
        :param address: 字符串形式的IP地址
        :return: 如果是有效地址则返回True，否则返回False
        """
        try:
            # 尝试创建 IPv4 或 IPv6 对象, 成功说明用户输入host合法
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def clear_display(self):
        """
        清屏按钮逻辑
        :return:
        """
        for i in self.packet_treeview.get_children():
            self.packet_treeview.delete(i)
        self.detail_text.delete('1.0', tk.END)
        self.stream_text.delete('1.0', tk.END)
        self.packets.clear()

    def packet_callback_filter(self, filter_packets: list):
        """
        渲染过滤后的filter_packets
        :param filter_packets:
        :return:
        """
        for i, pkt in enumerate(filter_packets, start=1):
            index = i
            ip_version = "/"
            protocol = "/"
            src = "/"
            dst = "/"
            if pkt.payload.name == "IP":
                ip_version = "IPv4"
                src = pkt.payload.src
                dst = pkt.payload.dst
                if pkt.payload.payload.name == "TCP":
                    protocol = "TCP"
                elif pkt.payload.payload.name == "UDP":
                    protocol = "UDP"
                elif pkt.payload.payload.name == "ICMPv6":
                    protocol = "ICMPv6"
            elif pkt.payload.name == "IPv6":
                ip_version = "IPv6"
                src = pkt.payload.src
                dst = pkt.payload.dst
                if pkt.payload.payload.name == "TCP":
                    protocol = "TCP"
                elif pkt.payload.payload.name == "UDP":
                    protocol = "UDP"
                elif pkt.payload.payload.name == "ICMPv6":
                    protocol = "ICMPv6"
            self.packet_treeview.insert("", tk.END, values=(index, ip_version, protocol, src, dst))


    def packet_callback(self, packet):
        """
        数据包处理函数
        :param packet:
        :return:
        """
        self.packets.append(packet)
        index = len(self.packets)

        ip_version = "/"
        protocol = "/"
        src = "/"
        dst = "/"

        if packet.payload.name == "IP":
            ip_version = "IPv4"
            src = packet.payload.src
            dst = packet.payload.dst
            if packet.payload.payload.name == "TCP":
                protocol = "TCP"
            elif packet.payload.payload.name == "UDP":
                protocol = "UDP"
            elif packet.payload.payload.name == "ICMPv6":
                protocol = "ICMPv6"
        elif packet.payload.name == "IPv6":
            ip_version = "IPv6"
            src = packet.payload.src
            dst = packet.payload.dst
            if packet.payload.payload.name == "TCP":
                protocol = "TCP"
            elif packet.payload.payload.name == "UDP":
                protocol = "UDP"
            elif packet.payload.payload.name == "ICMPv6":
                protocol = "ICMPv6"
        elif packet.payload.name == "ARP":  # 忽略ARP，否则引起内存溢出
            ip_version = "ARP"
        elif packet.payload.name == "LLC":  # 忽略LLC，否则引起内存溢出
            ip_version = "LLC"

        if ip_version in ["IPv4", "IPv6"] and protocol != "/":
            self.packet_treeview.insert("", tk.END, values=(index, ip_version, protocol, src, dst))
        else:
            self.packets.pop()


    def start_sniffer(self, interface, protocol_filter):
        """
        嗅探预处理逻辑
        :param interface:
        :param protocol_filter:
        :return:
        """
        self.sniffing = True
        filter_str = protocol_filter.lower()

        # 特定协议需要使用常用端口进行过滤
        if protocol_filter == "全部":
            filter_str = ""
        elif protocol_filter == "All/tcp":
            filter_str = "tcp"
        elif protocol_filter == "http/tcp":
            filter_str = "tcp port 80"
        elif protocol_filter == "https/tcp":
            filter_str = "tcp port 443"
        elif protocol_filter == "ftp/tcp":
            filter_str = "tcp port 21"
        elif protocol_filter == "ssh/tcp":
            filter_str = "tcp port 22"
        elif protocol_filter == "All/udp":
            filter_str = "udp"
        elif protocol_filter == "dns/udp":
            filter_str = "udp port 53"

        print(f"开始监听 {interface} 接口上的数据包，协议过滤器: {filter_str}...")
        try:
            if interface == "any":
                sniff(filter=filter_str, prn=self.packet_callback,
                      stop_filter=lambda x: not self.sniffing)
            else:
                sniff(iface=interface, filter=filter_str, prn=self.packet_callback,
                        stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            print(f"嗅探时出错: {e}")

    def on_start_sniff(self):
        """
        开始嗅探按钮捕捉函数
        :return:
        """
        self.start_button.config(state="disabled")
        self.interface_combo.config(state="disabled")
        self.protocol_combo.config(state="disabled")
        self.filter_button.config(state="disabled")
        self.reset_button.config(state="disabled")
        self.stop_button.config(state="normal")
        if not self.sniffing:
            interface = self.interfaces[self.interface_combo.current() - 1]
            protocol = self.protocol_combo.get()
            if self.interface_combo.get() == "全部":
                interface = "any"

            if interface:
                self.sniffing = True
                self.sniffer_thread = threading.Thread(target=self.start_sniffer, args=(interface, protocol))
                self.sniffer_thread.daemon = True
                self.sniffer_thread.start()
            else:
                print("请选择一个网络接口！")

    def on_stop_sniff(self):
        """
        停止嗅探按钮捕捉函数
        :return:
        """
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.interface_combo.config(state="normal")
        self.protocol_combo.config(state="normal")
        self.filter_button.config(state="normal")
        self.reset_button.config(state="normal")
        self.sniffing = False
        print("嗅探已停止")

    def get_tcp_stream(self, packet):
        """
        tcp流追踪处理逻辑
        :param packet:
        :return:
        """
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
        """
        追踪TCP流按钮捕捉函数
        :return:
        """
        selected_items = self.packet_treeview.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择一个TCP数据包！")
            return
        index = int(self.packet_treeview.item(selected_items[0])["values"][0]) - 1
        packet = self.packets[index]

        tcp_stream = self.get_tcp_stream(packet)
        new_window = tk.Toplevel(self.root)
        new_window.title("TCP流追踪")

        # 设置窗口尺寸
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

    def on_packet_select(self, event):
        """
        用户选中数据包捕获函数
        :param event:
        :return:
        """
        selected_items = self.packet_treeview.selection()
        if not selected_items:
            return
        index = int(self.packet_treeview.item(selected_items[0])["values"][0]) - 1
        packet = self.packets[index]

        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert(tk.END, str(packet.show(dump=True)).replace("###", ""))

        self.stream_text.delete('1.0', tk.END)
        hex_data = ' '.join(f"{byte:02x}" for byte in bytes(packet))
        self.stream_text.insert(tk.END, hex_data)


def main():
    """
    主函数
    :return:
    """
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    # 启动入口
    main()

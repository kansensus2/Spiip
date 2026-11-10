import threading
import time
import os
import queue
from datetime import datetime
import wave
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import sounddevice as sd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw

OUTPUT_DIR = "tv_monitor_logs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Словарь для расшифровки популярных сетевых портов телевизоров и IoT
KNOWN_PORTS = {
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Traffic)",
    443: "HTTPS (Secure Web Traffic)",
    1900: "SSDP / UPnP (Device Discovery)",
    5353: "mDNS (Multicast DNS Discovery)",
    8009: "Google Cast / Chromecast",
    8080: "HTTP Alternate / Media Proxy",
    8443: "HTTPS Alternate",
    9000: "Samsung SmartHub / DLNA",
    9197: "LG SmartShare / DLNA"
}

# Цветовые палитры (Light изменена на мягкие серые тона)
THEMES = {
    "dark": {
        "bg_main": "#0f0f0f",
        "bg_surface": "#212121",
        "bg_card": "#272727",
        "fg_text": "#f1f1f1",
        "fg_sub": "#aaa",
        "accent": "#ff0000",
        "console_bg": "#0f0f0f",
        "console_fg": "#2ba640",
        "entry_bg": "#0f0f0f",
        "entry_fg": "#3ea6ff",
        "badge_bg": "#272727",
        "badge_fg": "#aaa"
    },
    "light": {
        "bg_main": "#e4e6eb",  # Мягкий светло-серый фон окна (как в UI Windows/Discord)
        "bg_surface": "#f0f2f5",  # Карточки чуть светлее
        "bg_card": "#d8dadf",  # Элементы и кнопки
        "fg_text": "#1c1e21",  # Темный контрастный текст для читаемости
        "fg_sub": "#65676b",  # Второстепенный текст
        "accent": "#cc0000",  # Акцентный YouTube красный
        "console_bg": "#f0f2f5",  # Фон консоли в тон карточкам
        "console_fg": "#007000",  # Темно-зеленый текст логов
        "entry_bg": "#ffffff",  # Чисто-белые поля ввода для контраста
        "entry_fg": "#0056b3",  # Синий текст ввода
        "badge_bg": "#ced0d4",  # Бейдж статуса
        "badge_fg": "#1c1e21"
    }
}


class TVMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("YouTube Style | TV Security & Telemetry Hub")
        self.root.geometry("980x880")

        self.current_theme_key = "dark"
        self.t = THEMES[self.current_theme_key]

        self.root.configure(bg=self.t["bg_main"])

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.update_ttk_styles()

        self.running = False
        self.log_queue = queue.Queue()

        self.net_thread = None
        self.audio_threads = []
        self.log_file = None

        # Главный контейнер
        self.main_container = tk.Frame(root, bg=self.t["bg_main"])
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        # --- YOUTUBE HEADER ---
        self.header_frame = tk.Frame(self.main_container, bg=self.t["bg_surface"], bd=0, highlightthickness=0)
        self.header_frame.pack(fill=tk.X, pady=(0, 14), ipady=6)

        self.logo_lbl = tk.Label(self.header_frame, text="  ▶  TV PRIVACY MONITOR ", font=("Segoe UI", 12, "bold"),
                                 bg=self.t["bg_surface"], fg=self.t["accent"], anchor="w")
        self.logo_lbl.pack(side=tk.LEFT, padx=12, pady=6)

        # Кнопка переключения темы
        self.theme_btn = tk.Button(self.header_frame, text="🌙 Тёмная тема", font=("Segoe UI", 9, "bold"),
                                   bg=self.t["bg_card"], fg=self.t["fg_text"], relief=tk.FLAT, padx=10, pady=4,
                                   cursor="hand2", command=self.toggle_theme)
        self.theme_btn.pack(side=tk.RIGHT, padx=6, pady=6)

        self.status_badge = tk.Label(self.header_frame, text=" ● OFFLINE ", font=("Segoe UI", 9, "bold"),
                                     bg=self.t["badge_bg"], fg=self.t["badge_fg"], padx=10, pady=4)
        self.status_badge.pack(side=tk.RIGHT, padx=6, pady=6)

        # --- 1. ПАНЕЛЬ НАСТРОЙКИ ---
        self.settings_frame = tk.LabelFrame(self.main_container, text=" Параметры подключения ",
                                            font=("Segoe UI", 10, "bold"),
                                            bg=self.t["bg_surface"], fg=self.t["fg_sub"], bd=0, padx=16, pady=14)
        self.settings_frame.pack(fill=tk.X, pady=(0, 14))

        self.lbl_ip = tk.Label(self.settings_frame, text="IP телевизора:", font=("Segoe UI", 9),
                               bg=self.t["bg_surface"], fg=self.t["fg_text"])
        self.lbl_ip.grid(row=0, column=0, sticky="w", padx=4, pady=6)

        self.ip_entry = tk.Entry(self.settings_frame, font=("Segoe UI", 10, "bold"), bg=self.t["entry_bg"],
                                 fg=self.t["entry_fg"],
                                 insertbackground=self.t["fg_text"], relief=tk.FLAT, bd=8, width=16)
        self.ip_entry.insert(0, "192.168.1.50")
        self.ip_entry.grid(row=0, column=1, sticky="w", padx=4, pady=6)

        self.lbl_dev = tk.Label(self.settings_frame, text="Аудиоустройство:", font=("Segoe UI", 9),
                                bg=self.t["bg_surface"], fg=self.t["fg_text"])
        self.lbl_dev.grid(row=0, column=2, sticky="w", padx=16, pady=6)

        self.audio_devices = sd.query_devices()
        self.device_names = [f"[{i}] {d['name']} (Вх: {d['max_input_channels']})" for i, d in
                             enumerate(self.audio_devices)]

        self.device_combo = ttk.Combobox(self.settings_frame, values=self.device_names, width=32, state="readonly",
                                         font=("Segoe UI", 9))
        self.device_combo.grid(row=0, column=3, sticky="w", padx=4, pady=6)

        default_index = 0
        for i, name in enumerate(self.device_names):
            if "стерео" in name.lower() or "stereo" in name.lower():
                default_index = i
                break
        self.device_combo.current(default_index)

        self.save_txt_var = tk.BooleanVar(value=True)
        self.txt_check = tk.Checkbutton(self.settings_frame, text="Сохранять сеанс в текстовый лог (.txt)",
                                        variable=self.save_txt_var,
                                        font=("Segoe UI", 9), bg=self.t["bg_surface"], fg=self.t["fg_text"],
                                        selectcolor=self.t["bg_main"], activebackground=self.t["bg_surface"],
                                        activeforeground=self.t["fg_text"])
        self.txt_check.grid(row=1, column=0, columnspan=2, sticky="w", padx=4, pady=8)

        self.scan_all_var = tk.BooleanVar(value=False)
        self.scan_all_check = tk.Checkbutton(self.settings_frame, text="⚡ Мультискан ВСЕХ аудиовходов одновременно",
                                             variable=self.scan_all_var,
                                             font=("Segoe UI", 9, "bold"), bg=self.t["bg_surface"], fg="#d93829",
                                             selectcolor=self.t["bg_main"], activebackground=self.t["bg_surface"],
                                             activeforeground="#d93829")
        self.scan_all_check.grid(row=1, column=2, columnspan=2, sticky="w", padx=4, pady=8)

        # --- 2. ТЕЛЕМЕТРИЯ И VAD ---
        self.telemetry_frame = tk.Frame(self.main_container, bg=self.t["bg_surface"], bd=0)
        self.telemetry_frame.pack(fill=tk.X, pady=(0, 14))

        vad_subframe = tk.Frame(self.telemetry_frame, bg=self.t["bg_surface"], padx=14, pady=12)
        vad_subframe.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.lbl_vad = tk.Label(vad_subframe, text="Порог срабатывания VAD (Чувствительность):", font=("Segoe UI", 9),
                                bg=self.t["bg_surface"], fg=self.t["fg_sub"])
        self.lbl_vad.pack(anchor="w")

        self.threshold_slider = tk.Scale(vad_subframe, from_=50, to=1000, orient=tk.HORIZONTAL, length=320,
                                         bg=self.t["bg_surface"], fg=self.t["fg_text"],
                                         highlightbackground=self.t["bg_surface"],
                                         troughcolor=self.t["bg_main"], activebackground=self.t["accent"],
                                         font=("Segoe UI", 9))
        self.threshold_slider.set(250)
        self.threshold_slider.pack(anchor="w", pady=(6, 0))

        vu_subframe = tk.Frame(self.telemetry_frame, bg=self.t["bg_surface"], padx=14, pady=12)
        vu_subframe.pack(side=tk.RIGHT, fill=tk.X, expand=True)

        self.lbl_vu_title = tk.Label(vu_subframe, text="Мониторинг аудиопотока в реальном времени:",
                                     font=("Segoe UI", 9), bg=self.t["bg_surface"], fg=self.t["fg_sub"])
        self.lbl_vu_title.pack(anchor="w")

        vu_wrap = tk.Frame(vu_subframe, bg=self.t["bg_surface"])
        vu_wrap.pack(anchor="w", pady=(8, 0))

        self.vu_bar = ttk.Progressbar(vu_wrap, orient=tk.HORIZONTAL, length=260, mode="determinate", maximum=1000,
                                      style="Horizontal.TProgressbar")
        self.vu_bar.pack(side=tk.LEFT, padx=(0, 10))

        self.vu_label = tk.Label(vu_wrap, text="RMS: 0", font=("Consolas", 10, "bold"), bg=self.t["bg_surface"],
                                 fg="#238636", width=10)
        self.vu_label.pack(side=tk.LEFT)

        # --- 3. ПАНЕЛЬ ДЕЙСТВИЙ ---
        action_frame = tk.Frame(self.main_container, bg=self.t["bg_main"])
        action_frame.pack(fill=tk.X, pady=(0, 14))

        self.btn_start = tk.Button(action_frame, text="▶  ЗАПУСК МОНИТОРИНГА", bg=self.t["accent"], fg="white",
                                   font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=22, pady=10, cursor="hand2",
                                   command=self.start_monitoring)
        self.btn_start.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_stop = tk.Button(action_frame, text="⏹  СТОП", bg=self.t["bg_card"], fg=self.t["fg_sub"],
                                  font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=22, pady=10, state=tk.DISABLED,
                                  cursor="hand2", command=self.stop_monitoring)
        self.btn_stop.pack(side=tk.LEFT, padx=0)

        self.btn_open_folder = tk.Button(action_frame, text="📁  ПАПКА ЛОГОВ", bg=self.t["bg_card"],
                                         fg=self.t["entry_fg"],
                                         font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=18, pady=10,
                                         cursor="hand2", command=self.open_logs_folder)
        self.btn_open_folder.pack(side=tk.RIGHT, padx=0)

        # --- 4. КОНСОЛЬ ЛОГОВ ---
        console_frame = tk.Frame(self.main_container, bg=self.t["bg_surface"], bd=0)
        console_frame.pack(fill=tk.BOTH, expand=True)

        console_top = tk.Frame(console_frame, bg=self.t["bg_card"], padx=10, pady=6)
        console_top.pack(fill=tk.X)

        self.console_title_lbl = tk.Label(console_top, text="⚡ Real-time Telemetry Stream (DNS, SNI & Audio VAD)",
                                          font=("Segoe UI", 9, "bold"), bg=self.t["bg_card"], fg=self.t["fg_sub"])
        self.console_title_lbl.pack(side=tk.LEFT)

        self.log_area = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, bg=self.t["console_bg"],
                                                  fg=self.t["console_fg"], font=("Consolas", 9), bd=0,
                                                  highlightthickness=0)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.root.after(50, self.process_log_queue)

    def update_ttk_styles(self):
        self.style.configure(".", background=self.t["bg_main"], foreground=self.t["fg_text"],
                             fieldbackground=self.t["bg_surface"])
        self.style.configure("TCombobox", fieldbackground=self.t["bg_surface"], background=self.t["bg_card"],
                             foreground=self.t["fg_text"], selectbackground=self.t["accent"])
        self.style.map("TCombobox", fieldbackground=[('readonly', self.t["bg_surface"])])
        self.style.configure("Horizontal.TProgressbar", troughcolor=self.t["bg_surface"], background=self.t["accent"],
                             thickness=10)

    def toggle_theme(self):
        if self.current_theme_key == "dark":
            self.current_theme_key = "light"
            self.theme_btn.config(text="☀️ Светлая тема")
        else:
            self.current_theme_key = "dark"
            self.theme_btn.config(text="🌙 Тёмная тема")

        self.t = THEMES[self.current_theme_key]
        self.update_ttk_styles()

        self.root.configure(bg=self.t["bg_main"])
        self.main_container.configure(bg=self.t["bg_main"])

        self.header_frame.configure(bg=self.t["bg_surface"])
        self.logo_lbl.configure(bg=self.t["bg_surface"], fg=self.t["accent"])
        self.theme_btn.configure(bg=self.t["bg_card"], fg=self.t["fg_text"])
        self.status_badge.configure(bg=self.t["badge_bg"], fg=self.t["badge_fg"])

        self.settings_frame.configure(bg=self.t["bg_surface"], fg=self.t["fg_sub"])
        self.lbl_ip.configure(bg=self.t["bg_surface"], fg=self.t["fg_text"])
        self.ip_entry.configure(bg=self.t["entry_bg"], fg=self.t["entry_fg"], insertbackground=self.t["fg_text"])
        self.lbl_dev.configure(bg=self.t["bg_surface"], fg=self.t["fg_text"])

        self.txt_check.configure(bg=self.t["bg_surface"], fg=self.t["fg_text"], selectcolor=self.t["bg_main"],
                                 activebackground=self.t["bg_surface"], activeforeground=self.t["fg_text"])
        self.scan_all_check.configure(bg=self.t["bg_surface"], selectcolor=self.t["bg_main"],
                                      activebackground=self.t["bg_surface"])

        self.telemetry_frame.configure(bg=self.t["bg_surface"])
        for widget in self.telemetry_frame.winfo_children():
            widget.configure(bg=self.t["bg_surface"])
            for sub in widget.winfo_children():
                if isinstance(sub, tk.Label):
                    sub.configure(bg=self.t["bg_surface"], fg=self.t["fg_sub"] if sub != self.vu_label else "#238636")
                elif isinstance(sub, tk.Scale):
                    sub.configure(bg=self.t["bg_surface"], fg=self.t["fg_text"],
                                  highlightbackground=self.t["bg_surface"], troughcolor=self.t["bg_main"])
                elif isinstance(sub, tk.Frame):
                    sub.configure(bg=self.t["bg_surface"])

        for widget in self.main_container.winfo_children():
            if isinstance(widget, tk.Frame) and widget not in [self.header_frame, self.telemetry_frame]:
                widget.configure(bg=self.t["bg_main"])

        if self.running:
            self.btn_start.configure(bg="#3f3f3f", fg="#777")
            self.btn_stop.configure(bg=self.t["accent"], fg="white")
        else:
            self.btn_start.configure(bg=self.t["accent"], fg="white")
            self.btn_stop.configure(bg=self.t["bg_card"], fg=self.t["fg_sub"])

        self.btn_open_folder.configure(bg=self.t["bg_card"], fg=self.t["entry_fg"])
        self.log_area.configure(bg=self.t["console_bg"], fg=self.t["console_fg"])

    def log(self, message):
        self.log_queue.put(message)
        if self.save_txt_var.get() and self.log_file and not self.log_file.closed:
            try:
                self.log_file.write(message + "\n")
                self.log_file.flush()
            except Exception:
                pass

    def process_log_queue(self):
        while not self.log_queue.empty():
            item = self.log_queue.get_nowait()
            if isinstance(item, tuple) and item[0] == "RMS_UPDATE":
                rms_val = item[1]
                self.vu_bar['value'] = min(rms_val, 1000)
                self.vu_label.config(text=f"RMS: {int(rms_val)}")
            else:
                self.log_area.insert(tk.END, item + "\n")
                self.log_area.see(tk.END)
        self.root.after(50, self.process_log_queue)

    def open_logs_folder(self):
        folder_path = os.path.abspath(OUTPUT_DIR)
        if os.path.exists(folder_path):
            os.startfile(folder_path)
        else:
            messagebox.showwarning("Внимание", "Папка с логами еще не создана!")

    def start_monitoring(self):
        if self.running:
            return

        self.current_ip = self.ip_entry.get().strip()
        selected_combo_idx = self.device_combo.current()

        if not self.current_ip:
            messagebox.showerror("Ошибка", "Введите IP-адрес телевизора!")
            return

        if not self.scan_all_var.get() and selected_combo_idx == -1:
            messagebox.showerror("Ошибка", "Выберите аудиоустройство!")
            return

        self.current_device_id = selected_combo_idx

        timestamp_str = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        txt_filename = os.path.join(OUTPUT_DIR, f"session_log_{timestamp_str}.txt")
        if self.save_txt_var.get():
            try:
                self.log_file = open(txt_filename, "w", encoding="utf-8")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось создать .txt файл лога: {e}")
                return

        self.running = True
        self.ip_entry.config(state=tk.DISABLED)
        self.device_combo.config(state=tk.DISABLED)
        self.threshold_slider.config(state=tk.DISABLED)
        self.txt_check.config(state=tk.DISABLED)
        self.scan_all_check.config(state=tk.DISABLED)
        self.btn_start.config(state=tk.DISABLED, bg="#3f3f3f", fg="#777")
        self.btn_stop.config(state=tk.NORMAL, bg=self.t["accent"], fg="white")
        self.status_badge.config(text=" ● LIVE ", bg="#238636", fg="#ffffff")

        self.log("=" * 70)
        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] СТАРТ МОНИТОРИНГА [SOFT GRAY THEME]")
        self.log(f"   • Целевой IP: {self.current_ip}")
        if self.scan_all_var.get():
            self.log(f"   • Режим: МУЛЬТИСКАН ВСЕХ АУДИОВХОДОВ")
        else:
            self.log(f"   • Аудиоустройство ID: {self.current_device_id}")
        self.log(f"   • Порог VAD: {self.threshold_slider.get()}")
        if self.save_txt_var.get():
            self.log(f"   • Лог-файл: {txt_filename}")
        self.log("=" * 70)

        self.net_thread = threading.Thread(target=self.network_sniffer_worker, daemon=True)
        self.net_thread.start()

        if self.scan_all_var.get():
            for idx, dev in enumerate(self.audio_devices):
                if dev['max_input_channels'] > 0:
                    t = threading.Thread(target=self.single_device_scanner_worker, args=(idx, dev['name']), daemon=True)
                    t.start()
                    self.audio_threads.append(t)
        else:
            self.audio_thread = threading.Thread(target=self.audio_recorder_worker, daemon=True)
            self.audio_thread.start()

    def stop_monitoring(self):
        if not self.running:
            return

        self.running = False
        self.ip_entry.config(state=tk.NORMAL)
        self.device_combo.config(state=tk.NORMAL)
        self.threshold_slider.config(state=tk.NORMAL)
        self.txt_check.config(state=tk.NORMAL)
        self.scan_all_check.config(state=tk.NORMAL)
        self.btn_start.config(state=tk.NORMAL, bg=self.t["accent"], fg="white")
        self.btn_stop.config(state=tk.DISABLED, bg=self.t["bg_card"], fg=self.t["fg_sub"])
        self.status_badge.config(text=" ● OFFLINE ", bg=self.t["badge_bg"], fg=self.t["badge_fg"])

        self.vu_bar['value'] = 0
        self.vu_label.config(text="RMS: 0")
        self.log(f"\n[{datetime.now().strftime('%H:%M:%S')}] МОНИТОРИНГ ОСТАНОВЛЕН.")

        if self.log_file and not self.log_file.closed:
            try:
                self.log_file.close()
            except Exception:
                pass

    def extract_tls_sni(self, payload):
        try:
            if len(payload) > 43 and payload[0] == 0x16:
                if payload[5] == 0x01:
                    pos = 43
                    if pos >= len(payload):
                        return None
                    session_id_length = payload[pos]
                    pos += 1 + session_id_length

                    if pos + 2 >= len(payload):
                        return None
                    cipher_suites_length = int.from_bytes(payload[pos:pos + 2], 'big')
                    pos += 2 + cipher_suites_length

                    if pos + 1 >= len(payload):
                        return None
                    compression_methods_length = payload[pos]
                    pos += 1 + compression_methods_length

                    if pos + 2 >= len(payload):
                        return None
                    extensions_length = int.from_bytes(payload[pos:pos + 2], 'big')
                    pos += 2
                    end_pos = pos + extensions_length

                    while pos + 4 <= end_pos and pos + 4 <= len(payload):
                        ext_type = int.from_bytes(payload[pos:pos + 2], 'big')
                        ext_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
                        pos += 4
                        if ext_type == 0x0000:
                            if pos + 5 <= len(payload):
                                server_name_len = int.from_bytes(payload[pos + 3:pos + 5], 'big')
                                server_name_bytes = payload[pos + 5:pos + 5 + server_name_len]
                                return server_name_bytes.decode('utf-8', errors='ignore')
                        pos += ext_len
        except Exception:
            pass
        return None

    def network_sniffer_worker(self):
        def packet_callback(packet):
            if not self.running:
                return
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst

                proto = "TCP" if TCP in packet else ("UDP" if UDP in packet else "OTHER")
                dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
                sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)

                service_info = ""
                for p in (dport, sport):
                    if p in KNOWN_PORTS:
                        service_info = f" | 📌 [SERVICE]: {KNOWN_PORTS[p]}"
                        break

                domain_info = ""
                if DNS in packet and packet[DNS].qd:
                    try:
                        qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        domain_info = f" | 🌐 [DNS QUERY]: {qname}"
                    except Exception:
                        pass
                elif TCP in packet and Raw in packet:
                    payload = bytes(packet[Raw].load)
                    sni = self.extract_tls_sni(payload)
                    if sni:
                        domain_info = f" | 🔒 [TLS SNI / SITE]: {sni}"

                direction = "OUT ->" if src == self.current_ip else "IN  <-"
                target_ip = dst if src == self.current_ip else src

                log_line = f"[{datetime.now().strftime('%H:%M:%S')}] [{proto}] {direction} {target_ip}:{dport} (src: {sport}) | Size: {len(packet)} bytes{service_info}{domain_info}"
                self.log(log_line)

        try:
            self.log(f"[*] Сетевой сниффер активирован.")
            sniff(filter=f"host {self.current_ip}", prn=packet_callback, store=False,
                  stop_filter=lambda x: not self.running)
            self.log("[*] Сетевой сниффер остановлен.")
        except Exception as e:
            self.log(f"[!] Ошибка сниффера: {e}")

    def audio_recorder_worker(self):
        device_info = self.audio_devices[self.current_device_id]
        sample_rate = int(device_info.get('default_samplerate', 48000))
        if sample_rate == 0:
            sample_rate = 48000
        channels = max(1, min(2, device_info['max_input_channels']))

        self.log(f"[*] Аудиозахват запущен (ID: {self.current_device_id})")

        BLOCK_DURATION = 0.1
        block_size = int(sample_rate * BLOCK_DURATION)
        silence_timeout = 3.0
        recording_buffer = []
        is_recording = False
        silent_blocks_count = 0
        max_silent_blocks = int(silence_timeout / BLOCK_DURATION)

        try:
            with sd.InputStream(device=self.current_device_id, channels=channels, samplerate=sample_rate,
                                dtype='int16') as stream:
                while self.running:
                    current_threshold = self.threshold_slider.get()
                    audio_block, overflowed = stream.read(block_size)
                    if overflowed:
                        continue

                    data_float = audio_block.astype(np.float32)
                    rms = np.sqrt(np.mean(data_float ** 2))
                    self.log_queue.put(("RMS_UPDATE", rms))

                    if rms > current_threshold:
                        if not is_recording:
                            is_recording = True
                            self.log(f"[♪] Обнаружен звук (ID {self.current_device_id}) | RMS: {int(rms)}")
                            recording_buffer = []
                        silent_blocks_count = 0
                        recording_buffer.append(audio_block.copy())
                    else:
                        if is_recording:
                            silent_blocks_count += 1
                            recording_buffer.append(audio_block.copy())
                            if silent_blocks_count >= max_silent_blocks:
                                is_recording = False
                                full_audio = np.concatenate(recording_buffer, axis=0)
                                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                                filename = os.path.join(OUTPUT_DIR, f"audio_clip_{timestamp}.wav")
                                with wave.open(filename, 'wb') as wf:
                                    wf.setnchannels(channels)
                                    wf.setsampwidth(2)
                                    wf.setframerate(sample_rate)
                                    wf.writeframes(full_audio.tobytes())
                                self.log(f"[✔] Аудиофрагмент сохранен: {filename}")
                                recording_buffer = []
        except Exception as e:
            self.log(f"[!] Ошибка аудиозахвата: {e}")

    def single_device_scanner_worker(self, dev_id, dev_name):
        dev_info = self.audio_devices[dev_id]
        sample_rate = int(dev_info.get('default_samplerate', 48000))
        if sample_rate == 0:
            sample_rate = 48000
        channels = max(1, min(2, dev_info['max_input_channels']))

        BLOCK_DURATION = 0.2
        block_size = int(sample_rate * BLOCK_DURATION)
        silence_timeout = 3.0
        recording_buffer = []
        is_recording = False
        silent_blocks_count = 0
        max_silent_blocks = int(silence_timeout / BLOCK_DURATION)

        try:
            with sd.InputStream(device=dev_id, channels=channels, samplerate=sample_rate, dtype='int16') as stream:
                while self.running:
                    current_threshold = self.threshold_slider.get()
                    audio_block, overflowed = stream.read(block_size)
                    if overflowed:
                        continue

                    data_float = audio_block.astype(np.float32)
                    rms = np.sqrt(np.mean(data_float ** 2))

                    if rms > current_threshold:
                        self.log_queue.put(("RMS_UPDATE", rms))

                    if rms > current_threshold:
                        if not is_recording:
                            is_recording = True
                            self.log(f"[🔥 АКТИВНОСТЬ!] Мультискан [{dev_id}] {dev_name} | RMS: {int(rms)}")
                            recording_buffer = []
                        silent_blocks_count = 0
                        recording_buffer.append(audio_block.copy())
                    else:
                        if is_recording:
                            silent_blocks_count += 1
                            recording_buffer.append(audio_block.copy())
                            if silent_blocks_count >= max_silent_blocks:
                                is_recording = False
                                full_audio = np.concatenate(recording_buffer, axis=0)
                                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                                filename = os.path.join(OUTPUT_DIR, f"auto_audio_{dev_id}_{timestamp}.wav")
                                with wave.open(filename, 'wb') as wf:
                                    wf.setnchannels(channels)
                                    wf.setsampwidth(2)
                                    wf.setframerate(sample_rate)
                                    wf.writeframes(full_audio.tobytes())
                                self.log(f"[💾] Авто-аудио сохранено [{dev_id}]: {filename}")
                                recording_buffer = []
        except Exception:
            pass


if __name__ == "__main__":
    root = tk.Tk()
    app = TVMonitorApp(root)
    root.mainloop()
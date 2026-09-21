#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║   ███╗   ██╗██████╗ ██████╗     ███╗   ███╗ █████╗ ███████╗████████╗███████╗████╗║
║   ████╗  ██║██╔══██╗██╔══██╗    ████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══╝║
║   ██╔██╗ ██║██║  ██║██████╔╝    ██╔████╔██║███████║███████╗   ██║   █████╗  ██║   ║
║   ██║╚██╗██║██║  ██║██╔═══╝     ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██║   ║
║   ██║ ╚████║██████╔╝██║         ██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗█████╗║
║   ╚═╝  ╚═══╝╚═════╝ ╚═╝         ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚════╝║
║                                                                                  ║
║          NDP MASTER — Protocole Neighbor Discovery Protocol                      ║
║          Créé par hackers_tchad 🇹🇩                                               ║
║          Version 1.0.0 | Éducatif & Avancé                                       ║
╚══════════════════════════════════════════════════════════════════════════════════╝

⚠️  AVERTISSEMENT : Outil éducatif uniquement.
    Utilisez-le uniquement sur des réseaux autorisés.
"""

import os
import sys
import time
import json
import random
import socket
import struct
import argparse
import datetime
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, font as tkfont
from urllib.parse import urlparse

# Imports optionnels avec fallback
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class _DummyColor:
        def __getattr__(self, name):
            return ''
    Fore = Style = _DummyColor()

try:
    from tqdm import tqdm
except ImportError:
    class tqdm:
        def __init__(self, iterable=None, **kwargs):
            self.iterable = iterable
        def __iter__(self):
            for x in self.iterable:
                yield x
        def update(self, n=1):
            pass
        def close(self):
            pass

try:
    import requests
except ImportError:
    requests = None

try:
    from scapy.all import sniff, IPv6, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_Redirect, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════════════
# CONFIGURATION GLOBALE
# ═══════════════════════════════════════════════════════════════════════════════════
VERSION = "1.0.0"
AUTHOR = "hackers_tchad"
TITLE = "NDP MASTER"
THEME_BG = "#0a0f1c"
THEME_FG = "#00f0ff"
THEME_ACCENT = "#ff0055"
THEME_SECONDARY = "#00ff88"

NDP_MESSAGES = ["Router Solicitation", "Router Advertisement", "Neighbor Solicitation",
                "Neighbor Advertisement", "Redirect"]
NDP_PACKET_TYPES = {
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect"
}

SESSION_LOG = []
NEIGHBOR_TABLE = {}
ROUTER_TABLE = {}
PACKET_COUNT = {"RS": 0, "RA": 0, "NS": 0, "NA": 0, "Redirect": 0}
SNIFFING = False


def log_event(category, action, detail="", status="OK"):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "category": category,
        "action": action,
        "detail": detail,
        "status": status,
    }
    SESSION_LOG.append(entry)


def timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")


# ═══════════════════════════════════════════════════════════════════════════════════
# FENÊTRE PRINCIPALE TKINTER
# ═══════════════════════════════════════════════════════════════════════════════════
class NDPMasterApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{TITLE} v{VERSION} — by {AUTHOR}")
        self.root.configure(bg=THEME_BG)
        self.root.geometry("1400x900")
        self.root.state("zoomed")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TFrame", background=THEME_BG)
        self.style.configure("TLabel", background=THEME_BG, foreground=THEME_FG, font=("Consolas", 11))
        self.style.configure("TButton", background="#0d1b2a", foreground=THEME_FG,
                             font=("Consolas", 10, "bold"), borderwidth=2)
        self.style.map("TButton", background=[("active", "#1b3a4b")])
        self.style.configure("TNotebook", background=THEME_BG, tabmargins=[2, 5, 2, 0])
        self.style.configure("TNotebook.Tab", background="#0d1b2a", foreground=THEME_FG,
                             font=("Consolas", 10, "bold"), padding=[15, 5])
        self.style.map("TNotebook.Tab", background=[("selected", "#1b3a4b")], foreground=[("selected", "#ffffff")])

        self.build_menu()
        self.build_header()
        self.build_notebook()
        self.build_status_bar()

        self.terminal_queue = []
        self.after_id = None
        self.animate_header()

        log_event("SYSTEM", "app_started", f"{TITLE} v{VERSION}")

    def build_menu(self):
        menubar = tk.Menu(self.root, bg=THEME_BG, fg=THEME_FG, activebackground="#1b3a4b",
                          activeforeground=THEME_FG, font=("Consolas", 10))
        file_menu = tk.Menu(menubar, tearoff=0, bg=THEME_BG, fg=THEME_FG,
                            activebackground="#1b3a4b", activeforeground="#ffffff")
        file_menu.add_command(label="Exporter JSON", command=self.export_json)
        file_menu.add_command(label="Exporter CSV", command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit)
        menubar.add_cascade(label="Fichier", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0, bg=THEME_BG, fg=THEME_FG,
                             activebackground="#1b3a4b", activeforeground="#ffffff")
        tools_menu.add_command(label="Scanner NDP", command=self.scan_ndp)
        tools_menu.add_command(label="Envoyer RS", command=lambda: self.send_ndp("RS"))
        tools_menu.add_command(label="Envoyer RA", command=lambda: self.send_ndp("RA"))
        tools_menu.add_command(label="Envoyer NS", command=lambda: self.send_ndp("NS"))
        tools_menu.add_command(label="Envoyer NA", command=lambda: self.send_ndp("NA"))
        menubar.add_cascade(label="Outils NDP", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg=THEME_BG, fg=THEME_FG,
                            activebackground="#1b3a4b", activeforeground="#ffffff")
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="Quiz NDP", command=self.start_quiz)
        menubar.add_cascade(label="Aide", menu=help_menu)

        self.root.config(menu=menubar)

    def build_header(self):
        self.header_frame = tk.Frame(self.root, bg=THEME_BG, height=120)
        self.header_frame.pack(fill="x", padx=10, pady=10)
        self.header_frame.pack_propagate(False)

        self.title_label = tk.Label(self.header_frame, text=f"◈ {TITLE} ◈",
                                    bg=THEME_BG, fg=THEME_FG,
                                    font=("Orbitron", 32, "bold"))
        self.title_label.pack(pady=(15, 0))

        self.subtitle_label = tk.Label(self.header_frame,
                                       text=f"Protocole Neighbor Discovery Protocol | v{VERSION} | by {AUTHOR}",
                                       bg=THEME_BG, fg=THEME_SECONDARY,
                                       font=("Consolas", 12))
        self.subtitle_label.pack()

        self.status_header = tk.Label(self.header_frame,
                                      text="◉ Système prêt — Mode éducatif",
                                      bg=THEME_BG, fg=THEME_ACCENT,
                                      font=("Consolas", 10, "bold"))
        self.status_header.pack(pady=(5, 0))

    def animate_header(self):
        colors = ["#00f0ff", "#00ff88", "#ff0055", "#00f0ff"]
        current = getattr(self, "_anim_idx", 0)
        self.title_label.config(fg=colors[current % len(colors)])
        self._anim_idx = (current + 1) % len(colors)
        self.root.after(800, self.animate_header)

    def build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_overview = tk.Frame(self.notebook, bg=THEME_BG)
        self.tab_packets = tk.Frame(self.notebook, bg=THEME_BG)
        self.tab_neighbors = tk.Frame(self.notebook, bg=THEME_BG)
        self.tab_terminal = tk.Frame(self.notebook, bg=THEME_BG)
        self.tab_visual = tk.Frame(self.notebook, bg=THEME_BG)
        self.tab_security = tk.Frame(self.notebook, bg=THEME_BG)
        self.tab_quiz = tk.Frame(self.notebook, bg=THEME_BG)

        self.notebook.add(self.tab_overview, text="📘 Présentation")
        self.notebook.add(self.tab_packets, text="📦 Paquets NDP")
        self.notebook.add(self.tab_neighbors, text="🌐 Voisins")
        self.notebook.add(self.tab_terminal, text="💻 Terminal")
        self.notebook.add(self.tab_visual, text="🕸️ Visualisation")
        self.notebook.add(self.tab_security, text="🛡️ Sécurité")
        self.notebook.add(self.tab_quiz, text="❓ Quiz")

        self.build_overview_tab()
        self.build_packets_tab()
        self.build_neighbors_tab()
        self.build_terminal_tab()
        self.build_visual_tab()
        self.build_security_tab()
        self.build_quiz_tab()

    def build_overview_tab(self):
        frame = tk.Frame(self.tab_overview, bg=THEME_BG)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, bg="#0d1b2a", fg="#e0f7fa",
                                         font=("Consolas", 11), insertbackground=THEME_FG,
                                         padx=10, pady=10)
        text.pack(fill="both", expand=True)
        text.insert(tk.END, """
╔════════════════════════════════════════════════════════════════════════════════╗
║                    NEIGHBOR DISCOVERY PROTOCOL (NDP)                           ║
╚════════════════════════════════════════════════════════════════════════════════╝

📌 DEFINITION :
NDP (Neighbor Discovery Protocol) est un protocole de la couche réseau IPv6.
Il correspond à une combinaison améliorée des protocoles IPv4 ARP, ICMP Router Discovery
et ICMP Redirect. NDP est défini dans la RFC 4861.

🎯 A QUOI SERT NDP ?
- Découverte des routeurs sur un lien local.
- Découverte des préfixes et paramètres réseau.
- Résolution d'adresses (équivalent IPv6 d'ARP).
- Détermination de la reachability des voisins.
- Détection des adresses dupliquées (DAD).
- Redirection vers une meilleure route.

📦 TYPES DE MESSAGES NDP (ICMPv6) :
- Type 133 : Router Solicitation (RS)
- Type 134 : Router Advertisement (RA)
- Type 135 : Neighbor Solicitation (NS)
- Type 136 : Neighbor Advertisement (NA)
- Type 137 : Redirect

🔧 COMMANDES UTILES :
  Linux :
    ip -6 neighbor show
    ip -6 neighbor flush all
    ndisc6 <target-ipv6> <interface>
    rdisc6 <interface>

  Cisco IOS :
    show ipv6 neighbors
    show ipv6 interface brief
    ipv6 nd raguard

  Windows :
    netsh interface ipv6 show neighbors
    netsh interface ipv6 delete neighbors

⚠️ SECURITE NDP :
- RA Guard : filtrer les Router Advertisements non autorisés.
- ND Inspection : sécuriser la résolution d'adresses.
- SEND (Secure Neighbor Discovery) : authentification cryptographique NDP.
- IPv6 Source Guard : validation de l'origine des paquets.

        """)
        text.config(state=tk.DISABLED)

    def build_packets_tab(self):
        frame = tk.Frame(self.tab_packets, bg=THEME_BG)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        btn_frame = tk.Frame(frame, bg=THEME_BG)
        btn_frame.pack(fill="x", pady=5)

        for ptype, label in [("RS", "📤 Router Solicitation"), ("RA", "📥 Router Advertisement"),
                             ("NS", "🔍 Neighbor Solicitation"), ("NA", "✅ Neighbor Advertisement"),
                             ("Redirect", "↪️ Redirect")]:
            btn = tk.Button(btn_frame, text=label, bg="#0d1b2a", fg=THEME_FG,
                            activebackground="#1b3a4b", activeforeground="#ffffff",
                            font=("Consolas", 10, "bold"), width=22,
                            command=lambda t=ptype: self.send_ndp(t))
            btn.pack(side="left", padx=5)

        self.packet_tree = ttk.Treeview(frame, columns=("time", "type", "source", "target", "info"),
                                        show="headings", height=20)
        for col, txt in [("time", "Heure"), ("type", "Type"), ("source", "Source"),
                         ("target", "Cible"), ("info", "Info")]:
            self.packet_tree.heading(col, text=txt)
            self.packet_tree.column(col, width=180)
        self.packet_tree.pack(fill="both", expand=True, pady=10)

    def build_neighbors_tab(self):
        frame = tk.Frame(self.tab_neighbors, bg=THEME_BG)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        btn_frame = tk.Frame(frame, bg=THEME_BG)
        btn_frame.pack(fill="x", pady=5)

        tk.Button(btn_frame, text="🔄 Actualiser", bg="#0d1b2a", fg=THEME_FG,
                  activebackground="#1b3a4b", activeforeground="#ffffff",
                  font=("Consolas", 10, "bold"), command=self.refresh_neighbors).pack(side="left", padx=5)

        tk.Button(btn_frame, text="🧹 Vider la table", bg="#0d1b2a", fg=THEME_FG,
                  activebackground="#1b3a4b", activeforeground="#ffffff",
                  font=("Consolas", 10, "bold"), command=self.clear_neighbors).pack(side="left", padx=5)

        self.neighbor_tree = ttk.Treeview(frame, columns=("ipv6", "mac", "state", "interface", "last_seen"),
                                          show="headings", height=25)
        for col, txt in [("ipv6", "Adresse IPv6"), ("mac", "Adresse MAC"), ("state", "État"),
                         ("interface", "Interface"), ("last_seen", "Dernière vue")]:
            self.neighbor_tree.heading(col, text=txt)
            self.neighbor_tree.column(col, width=220)
        self.neighbor_tree.pack(fill="both", expand=True, pady=10)

    def build_terminal_tab(self):
        frame = tk.Frame(self.tab_terminal, bg=THEME_BG)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.terminal = scrolledtext.ScrolledText(frame, wrap=tk.WORD, bg="#050505", fg="#00ff00",
                                                  font=("Consolas", 11), insertbackground=THEME_FG,
                                                  padx=10, pady=10)
        self.terminal.pack(fill="both", expand=True)
        self.terminal.insert(tk.END, f"{TITLE} v{VERSION} Terminal [Prêt]\n")
        self.terminal.config(state=tk.DISABLED)

        input_frame = tk.Frame(frame, bg=THEME_BG)
        input_frame.pack(fill="x", pady=5)

        tk.Label(input_frame, text=">>>", bg=THEME_BG, fg=THEME_FG,
                 font=("Consolas", 12, "bold")).pack(side="left", padx=5)

        self.cmd_entry = tk.Entry(input_frame, bg="#0d1b2a", fg="#00ff00",
                                  font=("Consolas", 12), insertbackground=THEME_FG)
        self.cmd_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.cmd_entry.bind("<Return>", self.handle_command)

        tk.Button(input_frame, text="Exécuter", bg="#0d1b2a", fg=THEME_FG,
                  activebackground="#1b3a4b", activeforeground="#ffffff",
                  font=("Consolas", 10, "bold"), command=lambda: self.handle_command(None)).pack(side="left", padx=5)

    def build_visual_tab(self):
        frame = tk.Frame(self.tab_visual, bg=THEME_BG)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.visual_label = tk.Label(frame, text="Visualisation réseau (simulation 2D)",
                                     bg=THEME_BG, fg=THEME_FG, font=("Consolas", 14, "bold"))
        self.visual_label.pack(pady=10)

        self.canvas = tk.Canvas(frame, bg="#0a0f1c", highlightthickness=2,
                                highlightbackground=THEME_FG)
        self.canvas.pack(fill="both", expand=True)

        tk.Button(frame, text="🔄 Rafraîchir le graphe", bg="#0d1b2a", fg=THEME_FG,
                  activebackground="#1b3a4b", activeforeground="#ffffff",
                  font=("Consolas", 10, "bold"), command=self.draw_network).pack(pady=10)

        self.draw_network()

    def build_security_tab(self):
        frame = tk.Frame(self.tab_security, bg=THEME_BG)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, bg="#0d1b2a", fg="#e0f7fa",
                                         font=("Consolas", 11), insertbackground=THEME_FG,
                                         padx=10, pady=10)
        text.pack(fill="both", expand=True)
        text.insert(tk.END, """
╔════════════════════════════════════════════════════════════════════════════════╗
║                         SÉCURITÉ NDP                                           ║
╚════════════════════════════════════════════════════════════════════════════════╝

🛡️ MENACES NDP :
- Router Advertisement Spoofing : un attaquant envoie de faux RA pour devenir routeur par défaut.
- Neighbor Advertisement Spoofing : usurpation de voisin (équivalent ARP spoofing en IPv6).
- Redirect Attacks : détournement du trafic via des messages Redirect falsifiés.
- Duplicate Address Detection Denial of Service.

🔒 CONTRE-MESURES :
- RA Guard (RFC 6105) : bloquer les RA sur les ports non autorisés.
- ND Inspection / Snooping : valider les messages NS/NA.
- SEND (RFC 3971) : signatures cryptographiques pour NDP.
- DHCPv6 Guard : protéger les attributions DHCPv6.
- IPv6 Source Guard : vérifier l'origine des adresses.

📚 Ressources officielles :
- RFC 4861 : Neighbor Discovery for IP version 6 (IPv6)
- RFC 4862 : IPv6 Stateless Address Autoconfiguration
- RFC 3971 : SEcure Neighbor Discovery (SEND)
- RFC 6105 : IPv6 Router Advertisement Guard

        """)
        text.config(state=tk.DISABLED)

    def build_quiz_tab(self):
        frame = tk.Frame(self.tab_quiz, bg=THEME_BG)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.quiz_question = tk.Label(frame, text="Cliquez sur 'Nouvelle question' pour commencer",
                                      bg=THEME_BG, fg=THEME_FG, font=("Consolas", 14, "bold"),
                                      wraplength=1000, justify="center")
        self.quiz_question.pack(pady=30)

        self.quiz_buttons = []
        for i in range(4):
            btn = tk.Button(frame, text=f"Option {i+1}", bg="#0d1b2a", fg=THEME_FG,
                            activebackground="#1b3a4b", activeforeground="#ffffff",
                            font=("Consolas", 12), width=60,
                            command=lambda idx=i: self.check_answer(idx))
            btn.pack(pady=5)
            self.quiz_buttons.append(btn)

        self.quiz_feedback = tk.Label(frame, text="", bg=THEME_BG, fg=THEME_SECONDARY,
                                      font=("Consolas", 12, "bold"))
        self.quiz_feedback.pack(pady=20)

        tk.Button(frame, text="🔄 Nouvelle question", bg="#0d1b2a", fg=THEME_FG,
                  activebackground="#1b3a4b", activeforeground="#ffffff",
                  font=("Consolas", 11, "bold"), command=self.new_question).pack(pady=10)

        self.quiz_data = [
            ("Quel type ICMPv6 correspond au Router Solicitation ?", ["133", "134", "135", "136"], 0),
            ("Quel protocole IPv4 est remplacé par NDP pour la résolution d'adresses ?", ["DHCP", "ARP", "DNS", "OSPF"], 1),
            ("Quelle RFC définit NDP ?", ["RFC 4861", "RFC 1918", "RFC 793", "RFC 2544"], 0),
            ("Quel message NDP est utilisé pour la détection d'adresses dupliquées ?", ["RA", "NS", "RS", "Redirect"], 1),
            ("Quelle attaque NDP consiste à envoyer de faux Router Advertisements ?", ["NA Spoofing", "RA Spoofing", "Redirect", "DAD DoS"], 1),
        ]
        self.current_question = None
        self.current_answer = -1

    def build_status_bar(self):
        self.status_bar = tk.Label(self.root, text=f"◉ {TITLE} v{VERSION} | by {AUTHOR} | Prêt",
                                   bg="#0d1b2a", fg=THEME_FG, font=("Consolas", 10),
                                   anchor="w", padx=10)
        self.status_bar.pack(fill="x", side="bottom")

    def terminal_print(self, message, color="#00ff00"):
        self.terminal.config(state=tk.NORMAL)
        self.terminal.insert(tk.END, f"[{timestamp()}] {message}\n", color)
        self.terminal.see(tk.END)
        self.terminal.config(state=tk.DISABLED)

    def handle_command(self, event):
        cmd = self.cmd_entry.get().strip()
        self.cmd_entry.delete(0, tk.END)
        if not cmd:
            return
        self.terminal_print(f">>> {cmd}", "#00f0ff")

        parts = cmd.lower().split()
        if not parts:
            return

        if parts[0] == "help":
            self.terminal_print("Commandes : help, scan, send <rs|ra|ns|na|redirect>, show neighbors, show routers, clear, export <json|csv>, quiz, exit")
        elif parts[0] == "scan":
            self.scan_ndp()
        elif parts[0] == "send" and len(parts) > 1:
            self.send_ndp(parts[1].upper())
        elif parts[0] == "show" and len(parts) > 1 and parts[1] == "neighbors":
            self.refresh_neighbors()
        elif parts[0] == "show" and len(parts) > 1 and parts[1] == "routers":
            self.show_routers()
        elif parts[0] == "clear":
            self.terminal.config(state=tk.NORMAL)
            self.terminal.delete("1.0", tk.END)
            self.terminal.config(state=tk.DISABLED)
        elif parts[0] == "export" and len(parts) > 1:
            if parts[1] == "json":
                self.export_json()
            elif parts[1] == "csv":
                self.export_csv()
        elif parts[0] == "quiz":
            self.notebook.select(self.tab_quiz)
            self.new_question()
        elif parts[0] in ("exit", "quit"):
            self.root.quit()
        else:
            self.terminal_print(f"Commande inconnue : {cmd}", "#ff0055")

    def scan_ndp(self):
        self.terminal_print("Lancement du scan NDP simulé...", "#ffff00")
        for i in range(100):
            time.sleep(0.01)
            if i % 20 == 0:
                self.terminal_print(f"Progression : {i}%", "#aaaaaa")
        ipv6 = f"fe80::{random.randint(1000, 9999)}:{random.randint(1000, 9999)}:{random.randint(1000, 9999)}:{random.randint(1000, 9999)}"
        mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
        NEIGHBOR_TABLE[ipv6] = {"mac": mac, "state": "REACHABLE", "interface": "eth0", "last_seen": timestamp()}
        self.refresh_neighbors()
        self.terminal_print(f"Voisin découvert : {ipv6} -> {mac}", "#00ff88")
        log_event("NDP", "scan", ipv6)

    def send_ndp(self, ptype):
        if ptype not in ["RS", "RA", "NS", "NA", "REDIRECT"]:
            ptype = ptype.upper()
        if ptype == "REDIRECT":
            ptype = "Redirect"
        PACKET_COUNT[ptype] += 1
        src = f"fe80::{random.randint(1000, 9999)}:{random.randint(1000, 9999)}:{random.randint(1000, 9999)}:{random.randint(1000, 9999)}"
        tgt = f"ff02::{random.randint(1, 9)}"
        info_text = f"Type={NDP_PACKET_TYPES.get({'RS':133,'RA':134,'NS':135,'NA':136,'Redirect':137}[ptype], ptype)}"
        self.packet_tree.insert("", "end", values=(timestamp(), ptype, src, tgt, info_text))
        self.terminal_print(f"Envoi simulé : {ptype} de {src} vers {tgt}", "#00f0ff")
        log_event("NDP", f"send_{ptype.lower()}", f"{src} -> {tgt}")

    def refresh_neighbors(self):
        for item in self.neighbor_tree.get_children():
            self.neighbor_tree.delete(item)
        for ipv6, data in NEIGHBOR_TABLE.items():
            self.neighbor_tree.insert("", "end", values=(ipv6, data["mac"], data["state"],
                                                          data["interface"], data["last_seen"]))
        self.terminal_print(f"Table de voisins : {len(NEIGHBOR_TABLE)} entrée(s)", "#00ff88")

    def clear_neighbors(self):
        NEIGHBOR_TABLE.clear()
        self.refresh_neighbors()
        self.terminal_print("Table de voisins vidée.", "#ff0055")

    def show_routers(self):
        self.terminal_print(f"Routeurs découverts : {len(ROUTER_TABLE)}", "#00f0ff")
        for r, d in ROUTER_TABLE.items():
            self.terminal_print(f"  {r} -> {d}", "#aaaaaa")

    def draw_network(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width() or 800
        h = self.canvas.winfo_height() or 500
        cx, cy = w // 2, h // 2

        nodes = list(NEIGHBOR_TABLE.keys()) or ["Router", "Host A", "Host B"]
        radius = min(w, h) // 3
        angle_step = 360 / max(len(nodes), 1)

        self.canvas.create_oval(cx-20, cy-20, cx+20, cy+20, fill=THEME_ACCENT, outline="#fff", width=2)
        self.canvas.create_text(cx, cy, text="YOU", fill="#fff", font=("Consolas", 10, "bold"))

        for i, node in enumerate(nodes):
            angle = math.radians(i * angle_step)
            nx = cx + radius * math.cos(angle)
            ny = cy + radius * math.sin(angle)
            self.canvas.create_line(cx, cy, nx, ny, fill=THEME_FG, width=2)
            self.canvas.create_oval(nx-15, ny-15, nx+15, ny+15, fill=THEME_SECONDARY, outline="#fff", width=2)
            self.canvas.create_text(nx, ny, text=node[-8:], fill="#000", font=("Consolas", 8, "bold"))

    def export_json(self):
        filename = f"ndp_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = {
            "generated_at": datetime.datetime.now().isoformat(),
            "version": VERSION,
            "author": AUTHOR,
            "neighbors": NEIGHBOR_TABLE,
            "routers": ROUTER_TABLE,
            "packet_count": PACKET_COUNT,
            "events": SESSION_LOG,
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self.terminal_print(f"Export JSON : {filename}", "#00ff88")
        log_event("EXPORT", "json", filename)

    def export_csv(self):
        filename = f"ndp_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("timestamp,category,action,detail,status\n")
            for e in SESSION_LOG:
                f.write(f"{e['timestamp']},{e['category']},{e['action']},{e['detail']},{e['status']}\n")
        self.terminal_print(f"Export CSV : {filename}", "#00ff88")
        log_event("EXPORT", "csv", filename)

    def show_docs(self):
        messagebox.showinfo("Documentation NDP",
                            "NDP (Neighbor Discovery Protocol) est défini dans la RFC 4861.\n\n"
                            "Il remplace ARP en IPv6 et permet la découverte des routeurs,\n"
                            "la résolution d'adresses, la détection d'adresses dupliquées\n"
                            "et la redirection de routes.")

    def new_question(self):
        q = random.choice(self.quiz_data)
        self.current_question = q
        self.current_answer = q[2]
        self.quiz_question.config(text=q[0])
        for i, btn in enumerate(self.quiz_buttons):
            btn.config(text=q[1][i], bg="#0d1b2a")
        self.quiz_feedback.config(text="")

    def check_answer(self, idx):
        if idx == self.current_answer:
            self.quiz_feedback.config(text="✅ Bonne réponse !", fg=THEME_SECONDARY)
            self.quiz_buttons[idx].config(bg="#004d00")
        else:
            self.quiz_feedback.config(text="❌ Mauvaise réponse.", fg=THEME_ACCENT)
            self.quiz_buttons[idx].config(bg="#4d0000")


# ═══════════════════════════════════════════════════════════════════════════════════
# LANCEMENT
# ═══════════════════════════════════════════════════════════════════════════════════
import math

def main():
    parser = argparse.ArgumentParser(description=f"{TITLE} — {AUTHOR}")
    parser.add_argument("--auto", action="store_true", help="Lancer automatiquement l'interface")
    args = parser.parse_args()

    root = tk.Tk()
    app = NDPMasterApp(root)
    if args.auto:
        app.terminal_print("Mode automatique activé.", "#00f0ff")
    root.mainloop()


if __name__ == "__main__":
    main()

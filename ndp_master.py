#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 NDP ADVANCED VISUALIZATION & DIAGNOSTIC TOOLKIT
 Créé par : hackers_tchad
 Version  : 3.0.0 - Pro
 Protocole: NDP (Neighbor Discovery Protocol) - IPv6
 Description:
   Ce script Python avancé fournit une interface graphique Tkinter stylisée
   permettant de visualiser, simuler, analyser et apprendre le protocole NDP
   utilisé dans les réseaux IPv6. Il inclut des animations 3D simulées, des
   captures de paquets, des statistiques en temps réel, un terminal intégré,
   des définitions pédagogiques et des commandes réseau courantes.
================================================================================
"""

# ==============================================================================
#  SECTION 1 : IMPORTATIONS
# ==============================================================================

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, font as tkfont
import random
import socket
import struct
import threading
import time
import datetime
import os
import sys
import json
import math
import re
import subprocess
import platform
from collections import deque, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Callable

# ==============================================================================
#  SECTION 2 : CONSTANTES GLOBALES ET CONFIGURATION
# ==============================================================================

APP_TITLE = "NDP Advanced Toolkit"
APP_VERSION = "3.0.0"
APP_AUTHOR = "hackers_tchad"
APP_THEME = "dark"

# Couleurs du thème sombre néon
COLORS = {
    "bg_primary": "#0a0a12",
    "bg_secondary": "#12121f",
    "bg_tertiary": "#1a1a2e",
    "accent_cyan": "#00f0ff",
    "accent_magenta": "#ff00ff",
    "accent_green": "#00ff88",
    "accent_yellow": "#ffcc00",
    "accent_red": "#ff3366",
    "accent_orange": "#ff8800",
    "text_primary": "#e0e0e0",
    "text_secondary": "#a0a0a0",
    "text_dim": "#606070",
    "border": "#2a2a40",
    "grid": "#1f1f33",
    "packet_rs": "#ff3366",
    "packet_ra": "#00f0ff",
    "packet_ns": "#ffcc00",
    "packet_na": "#00ff88",
    "packet_redirect": "#ff8800",
}

# Types de messages NDP avec leurs codes ICMPv6
NDP_MESSAGE_TYPES = {
    "Router Solicitation (RS)":    {"code": 133, "color": "packet_rs",    "desc": "Un hôte demande l'envoi immédiat de Router Advertisements."},
    "Router Advertisement (RA)":   {"code": 134, "color": "packet_ra",    "desc": "Un routeur annonce sa présence et les paramètres du lien."},
    "Neighbor Solicitation (NS)":  {"code": 135, "color": "packet_ns",    "desc": "Un nœud demande l'adresse MAC d'un voisin ou vérifie sa disponibilité."},
    "Neighbor Advertisement (NA)": {"code": 136, "color": "packet_na",    "desc": "Un nœud répond avec son adresse MAC ou confirme sa présence."},
    "Redirect":                    {"code": 137, "color": "packet_redirect","desc": "Un routeur informe un hôte d'une meilleure route."},
}

# Options NDP
NDP_OPTIONS = {
    1: "Source Link-Layer Address",
    2: "Target Link-Layer Address",
    3: "Prefix Information",
    4: "Redirected Header",
    5: "MTU",
}

# Commandes utiles par OS
COMMANDS_BY_OS = {
    "Windows": {
        "Afficher la table de voisinage":   "netsh interface ipv6 show neighbors",
        "Vider la table de voisinage":      "netsh interface ipv6 delete neighbors",
        "Afficher les routes IPv6":         "netsh interface ipv6 show route",
        "Statistiques IPv6":                "netsh interface ipv6 show ipstats",
        "Informations interface":           "netsh interface ipv6 show interface",
        "Ping IPv6":                        "ping -6 google.com",
        "Traceroute IPv6":                  "tracert -6 google.com",
        "Configuration IP":                 "ipconfig /all",
    },
    "Linux": {
        "Afficher la table de voisinage":   "ip -6 neigh show",
        "Vider la table de voisinage":      "ip -6 neigh flush all",
        "Afficher les routes IPv6":         "ip -6 route show",
        "Statistiques IPv6":                "ip -6 -s -s link show",
        "Informations interface":           "ip -6 addr show",
        "Ping IPv6":                        "ping6 -c 4 google.com",
        "Traceroute IPv6":                  "traceroute6 google.com",
        "Configuration IP":                 "ip addr show",
    },
    "Darwin": {
        "Afficher la table de voisinage":   "ndp -a",
        "Vider la table de voisinage":      "ndp -c",
        "Afficher les routes IPv6":         "netstat -rn -f inet6",
        "Statistiques IPv6":                "netstat -s -f inet6",
        "Informations interface":           "ifconfig",
        "Ping IPv6":                        "ping6 -c 4 google.com",
        "Traceroute IPv6":                  "traceroute6 google.com",
        "Configuration IP":                 "ifconfig",
    },
}

# Statistiques mondiales estimées (données illustratives)
GLOBAL_IPV6_STATS = {
    "Adresses IPv6 uniques allouées": "340 undécillions par sous-réseau /64",
    "Taux d'adoption mondial IPv6": "~42% (2024)",
    "Pays leader IPv6": "Inde (~70%), France (~75%), Allemagne (~65%)",
    "Organismes de standardisation": "IETF (RFC 4861, RFC 4862)",
    "RFC principale NDP": "RFC 4861 - Neighbor Discovery for IP Version 6",
    "RFC autoconfiguration": "RFC 4862 - IPv6 Stateless Address Autoconfiguration",
}

# Numéros d'urgence par pays
EMERGENCY_NUMBERS = {
    "Tchad": {"police": "17", "pompiers": "18", "samu": "2251-4242", "international": "112"},
    "France": {"police": "17", "pompiers": "18", "samu": "15", "international": "112"},
    "États-Unis": {"police": "911", "pompiers": "911", "samu": "911", "international": "911"},
    "Royaume-Uni": {"police": "999", "pompiers": "999", "samu": "999", "international": "112"},
    "Allemagne": {"police": "110", "pompiers": "112", "samu": "112", "international": "112"},
    "Inde": {"police": "100", "pompiers": "101", "samu": "108", "international": "112"},
    "Japon": {"police": "110", "pompiers": "119", "samu": "119", "international": "112"},
    "Brésil": {"police": "190", "pompiers": "193", "samu": "192", "international": "188"},
    "Australie": {"police": "000", "pompiers": "000", "samu": "000", "international": "000"},
    "Canada": {"police": "911", "pompiers": "911", "samu": "911", "international": "911"},
    "Chine": {"police": "110", "pompiers": "119", "samu": "120", "international": "112"},
    "Russie": {"police": "102", "pompiers": "101", "samu": "103", "international": "112"},
    "Afrique du Sud": {"police": "10111", "pompiers": "10177", "samu": "10177", "international": "112"},
    "Nigeria": {"police": "112", "pompiers": "112", "samu": "112", "international": "112"},
    "Égypte": {"police": "122", "pompiers": "180", "samu": "123", "international": "112"},
}

# ==============================================================================
#  SECTION 3 : CLASSES DE DONNÉES
# ==============================================================================

@dataclass
class NdpPacket:
    """Représente un paquet NDP pour la simulation."""
    msg_type: str
    source_ip: str
    target_ip: str
    source_mac: str
    target_mac: str
    timestamp: float = field(default_factory=time.time)
    ttl: int = 255
    hop_limit: int = 255
    options: List[Tuple[int, str]] = field(default_factory=list)
    sequence: int = 0

    def to_dict(self) -> Dict:
        return {
            "Type": self.msg_type,
            "Source IP": self.source_ip,
            "Target IP": self.target_ip,
            "Source MAC": self.source_mac,
            "Target MAC": self.target_mac,
            "TTL": self.ttl,
            "Hop Limit": self.hop_limit,
            "Options": self.options,
            "Timestamp": datetime.datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3],
            "Sequence": self.sequence,
        }


@dataclass
class NetworkNode:
    """Représente un nœud du réseau dans la simulation 3D."""
    node_id: str
    ip: str
    mac: str
    x: float
    y: float
    z: float
    node_type: str = "host"  # host, router, gateway
    is_online: bool = True
    last_seen: float = field(default_factory=time.time)
    neighbors: List[str] = field(default_factory=list)


# ==============================================================================
#  SECTION 4 : BASE DE DONNÉES DE DÉFINITIONS NDP
# ==============================================================================

NDP_DEFINITIONS = {
    "NDP (Neighbor Discovery Protocol)": {
        "definition": "Protocole de la couche réseau (couche 3) utilisé avec IPv6 pour découvrir les autres nœuds sur un lien local, déterminer leurs adresses MAC, trouver des routeurs, maintenir les informations de voisinage et détecter les adresses dupliquées (DAD).",
        "usage": "Remplace ARP, ICMP Router Discovery et ICMP Redirect d'IPv4.",
        "couche": "Réseau (L3) - utilise ICMPv6",
        "rfc": "RFC 4861",
    },
    "Router Solicitation (RS)": {
        "definition": "Message ICMPv6 type 133 envoyé par un hôte au démarrage pour demander aux routeurs de transmettre immédiatement des Router Advertisements.",
        "usage": "Accélère l'obtention des paramètres réseau (préfixe, MTU, passerelle).",
        "couche": "ICMPv6",
        "rfc": "RFC 4861 §4.1",
    },
    "Router Advertisement (RA)": {
        "definition": "Message ICMPv6 type 134 envoyé périodiquement par les routeurs ou en réponse à une RS. Il contient des options comme les préfixes, la MTU et les drapeaux de configuration.",
        "usage": "Permet l'autoconfiguration sans état (SLAAC) et informe les hôtes de la présence du routeur.",
        "couche": "ICMPv6",
        "rfc": "RFC 4861 §4.2",
    },
    "Neighbor Solicitation (NS)": {
        "definition": "Message ICMPv6 type 135 envoyé pour demander l'adresse de liaison d'un voisin ou pour vérifier qu'un voisin est toujours joignable (Reachability Detection).",
        "usage": "Résolution d'adresse et vérification de la disponibilité d'un voisin.",
        "couche": "ICMPv6",
        "rfc": "RFC 4861 §4.3",
    },
    "Neighbor Advertisement (NA)": {
        "definition": "Message ICMPv6 type 136 envoyé en réponse à une NS ou spontanément quand une adresse MAC change. Il informe les autres nœuds de l'adresse de liaison du nœud.",
        "usage": "Fournit l'association IPv6 ↔ MAC demandée.",
        "couche": "ICMPv6",
        "rfc": "RFC 4861 §4.4",
    },
    "Redirect": {
        "definition": "Message ICMPv6 type 137 envoyé par un routeur pour informer un hôte qu'une route plus optimale existe pour une destination donnée.",
        "usage": "Optimisation du routage sur le lien local.",
        "couche": "ICMPv6",
        "rfc": "RFC 4861 §4.5",
    },
    "DAD (Duplicate Address Detection)": {
        "definition": "Mécanisme par lequel un nœud vérifie qu'une adresse IPv6 qu'il souhaite utiliser n'est pas déjà attribuée à un autre nœud sur le lien local.",
        "usage": "Évite les conflits d'adresses IPv6.",
        "couche": "NDP / ICMPv6 NS",
        "rfc": "RFC 4862",
    },
    "SLAAC (Stateless Address Autoconfiguration)": {
        "definition": "Mécanisme permettant à un hôte IPv6 de configurer automatiquement ses adresses sans serveur DHCPv6, en combinant le préfixe annoncé par le routeur et son identifiant d'interface.",
        "usage": "Configuration automatique des adresses IPv6.",
        "couche": "IPv6 / NDP",
        "rfc": "RFC 4862",
    },
    "Adresse lien-local": {
        "definition": "Adresse IPv6 commençant par fe80::/10, valide uniquement sur le segment réseau local. Elle est utilisée par NDP pour la découverte de voisins.",
        "usage": "Communication locale et échange de messages NDP.",
        "couche": "IPv6",
        "rfc": "RFC 4291",
    },
    "Adresse multicast sollicitée": {
        "definition": "Adresse multicast dérivée de l'adresse IPv6 cible (ff02::1:ffxx:xxxx) utilisée par les messages Neighbor Solicitation pour interroger un seul hôte sans inonder tout le réseau.",
        "usage": "Résolution d'adresse ciblée.",
        "couche": "IPv6 Multicast",
        "rfc": "RFC 4861 §7",
    },
    "ICMPv6": {
        "definition": "Version d'ICMP adaptée à IPv6. Elle intègre les fonctions d'erreur (Destination Unreachable, Time Exceeded) et d'information (Echo Request/Reply) ainsi que NDP.",
        "usage": "Supporte NDP, ping6 et la signalisation d'erreurs IPv6.",
        "couche": "Réseau (L3)",
        "rfc": "RFC 4443",
    },
    "Neighbor Cache": {
        "definition": "Table stockée par un nœud IPv6 contenant l'état de joignabilité de ses voisins (INCOMPLETE, REACHABLE, STALE, DELAY, PROBE).",
        "usage": "Évite les requêtes NDP répétées et détecte les voisins inaccessibles.",
        "couche": "NDP / Système d'exploitation",
        "rfc": "RFC 4861 §7.3",
    },
    "Reachability Detection": {
        "definition": "Processus NDP vérifiant périodiquement qu'un voisin est encore joignable, en passant par les états STALE, DELAY puis PROBE si nécessaire.",
        "usage": "Maintient à jour la table de voisinage et détecte les défaillances.",
        "couche": "NDP",
        "rfc": "RFC 4861 §7.3",
    },
}

# ==============================================================================
#  SECTION 5 : FONCTIONS UTILITAIRES
# ==============================================================================

def generate_ipv6(prefix: str = "2001:db8", suffix: str = None) -> str:
    """Génère une adresse IPv6 aléatoire."""
    if suffix:
        return f"{prefix}::{suffix}"
    parts = [format(random.randint(0, 65535), 'x') for _ in range(4)]
    return f"{prefix}:{':'.join(parts)}"


def generate_mac() -> str:
    """Génère une adresse MAC aléatoire locale."""
    return ":".join([format(random.randint(0x00, 0xff), '02x') for _ in range(6)])


def solicited_node_multicast(ip: str) -> str:
    """Calcure l'adresse multicast sollicitée à partir d'une IPv6."""
    parts = ip.split(":")
    if len(parts) >= 2:
        last = parts[-1] if parts[-1] else parts[-2]
        last_full = last.zfill(4)
        return f"ff02::1:ff{last_full[-2:]}:{last_full[-4:]}"
    return "ff02::1:ff00:1"


def format_packet_log(packet: NdpPacket) -> str:
    """Formate un paquet NDP pour l'affichage."""
    code = NDP_MESSAGE_TYPES.get(packet.msg_type, {}).get("code", "?")
    opts = ", ".join([f"{NDP_OPTIONS.get(o[0], o[0])}={o[1]}" for o in packet.options]) or "Aucune"
    return (
        f"[{datetime.datetime.fromtimestamp(packet.timestamp).strftime('%H:%M:%S.%f')[:-3]}] "
        f"ICMPv6 Type={code} ({packet.msg_type}) | "
        f"Src={packet.source_ip} ({packet.source_mac}) -> "
        f"Dst={packet.target_ip} ({packet.target_mac}) | "
        f"HopLimit={packet.hop_limit} | Seq={packet.sequence} | Options=[{opts}]"
    )


# ==============================================================================
#  SECTION 6 : CLASSE PRINCIPALE DE L'INTERFACE
# ==============================================================================

class NdpAdvancedToolkit:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_TITLE} v{APP_VERSION} | by {APP_AUTHOR}")
        self.root.geometry("1600x1000")
        self.root.configure(bg=COLORS["bg_primary"])
        self.root.minsize(1400, 900)

        # Variables d'état
        self.nodes: Dict[str, NetworkNode] = {}
        self.packets: deque = deque(maxlen=1000)
        self.simulation_running = False
        self.packet_counter = 0
        self.selected_node_id: Optional[str] = None
        self.animation_speed = tk.DoubleVar(value=1.0)
        self.packet_rate = tk.IntVar(value=5)
        self.auto_scroll = tk.BooleanVar(value=True)
        self.show_grid = tk.BooleanVar(value=True)
        self.rotation_angle = 0.0
        self.animations: List[Dict] = []
        self.current_os = platform.system()
        if self.current_os not in COMMANDS_BY_OS:
            self.current_os = "Linux"

        # Police
        self.font_main = tkfont.Font(family="Consolas", size=10)
        self.font_title = tkfont.Font(family="Segoe UI", size=14, weight="bold")
        self.font_mono = tkfont.Font(family="Courier New", size=9)

        # Configuration des styles ttk
        self._setup_styles()

        # Construction de l'interface
        self._build_menu()
        self._build_main_layout()
        self._initialize_default_network()

        # Thread de simulation
        self.sim_thread = threading.Thread(target=self._simulation_loop, daemon=True)
        self.sim_thread.start()

        # Démarrage de l'animation
        self._animate()

    # --------------------------------------------------------------------------
    #  STYLES
    # --------------------------------------------------------------------------
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=COLORS["bg_secondary"])
        style.configure("TLabel", background=COLORS["bg_secondary"], foreground=COLORS["text_primary"], font=("Segoe UI", 10))
        style.configure("TButton", background=COLORS["bg_tertiary"], foreground=COLORS["text_primary"], font=("Segoe UI", 9), borderwidth=1)
        style.map("TButton", background=[("active", COLORS["accent_cyan"])], foreground=[("active", COLORS["bg_primary"])])
        style.configure("TNotebook", background=COLORS["bg_primary"], tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background=COLORS["bg_tertiary"], foreground=COLORS["text_secondary"], padding=[15, 5], font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", COLORS["accent_cyan"])], foreground=[("selected", COLORS["bg_primary"])])
        style.configure("Horizontal.TScale", background=COLORS["bg_secondary"], troughcolor=COLORS["bg_tertiary"])
        style.configure("TCheckbutton", background=COLORS["bg_secondary"], foreground=COLORS["text_primary"])

    # --------------------------------------------------------------------------
    #  MENU
    # --------------------------------------------------------------------------
    def _build_menu(self):
        menubar = tk.Menu(self.root, bg=COLORS["bg_tertiary"], fg=COLORS["text_primary"], activebackground=COLORS["accent_cyan"], activeforeground=COLORS["bg_primary"])
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_tertiary"], fg=COLORS["text_primary"])
        file_menu.add_command(label="Nouvelle simulation", command=self._reset_simulation)
        file_menu.add_command(label="Exporter les paquets (JSON)", command=self._export_packets)
        file_menu.add_command(label="Exporter la capture (TXT)", command=self._export_capture)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit)
        menubar.add_cascade(label="Fichier", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_tertiary"], fg=COLORS["text_primary"])
        tools_menu.add_command(label="Générer un paquet personnalisé", command=self._open_custom_packet_dialog)
        tools_menu.add_command(label="Exécuter une commande réseau", command=self._open_command_dialog)
        tools_menu.add_command(label="Vérifier la connectivité IPv6", command=self._check_ipv6_connectivity)
        tools_menu.add_command(label="Numéros d'urgence mondiaux", command=self._open_emergency_map)
        menubar.add_cascade(label="Outils", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_tertiary"], fg=COLORS["text_primary"])
        help_menu.add_command(label="Définitions NDP", command=lambda: self.notebook.select(self.tab_definitions))
        help_menu.add_command(label="À propos", command=self._show_about)
        menubar.add_cascade(label="Aide", menu=help_menu)

    # --------------------------------------------------------------------------
    #  LAYOUT PRINCIPAL
    # --------------------------------------------------------------------------
    def _build_main_layout(self):
        main_paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=COLORS["border"], sashwidth=6)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left_frame = tk.Frame(main_paned, bg=COLORS["bg_secondary"], bd=2, relief=tk.RIDGE)
        main_paned.add(left_frame, minsize=800)
        self._build_visualization_panel(left_frame)

        right_frame = tk.Frame(main_paned, bg=COLORS["bg_secondary"], bd=2, relief=tk.RIDGE)
        main_paned.add(right_frame, minsize=500)
        self._build_tabs_panel(right_frame)

        self.status_var = tk.StringVar(value="Prêt | Simulation en pause")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bg=COLORS["bg_tertiary"], fg=COLORS["accent_cyan"], font=("Consolas", 9), anchor=tk.W, padx=10)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    # --------------------------------------------------------------------------
    #  PANNEAU DE VISUALISATION 3D
    # --------------------------------------------------------------------------
    def _build_visualization_panel(self, parent):
        header = tk.Frame(parent, bg=COLORS["bg_tertiary"], height=40)
        header.pack(fill=tk.X, pady=(0, 2))
        tk.Label(header, text="🌐 Visualisation NDP 3D", bg=COLORS["bg_tertiary"], fg=COLORS["accent_cyan"], font=self.font_title).pack(side=tk.LEFT, padx=10, pady=5)

        self.canvas_3d = tk.Canvas(parent, bg=COLORS["bg_primary"], highlightthickness=0)
        self.canvas_3d.pack(fill=tk.BOTH, expand=True)
        self.canvas_3d.bind("<Button-1>", self._on_canvas_click)

        controls = tk.Frame(parent, bg=COLORS["bg_secondary"], height=50)
        controls.pack(fill=tk.X, pady=(2, 0))

        self.btn_start = tk.Button(controls, text="▶ Démarrer", bg=COLORS["accent_green"], fg=COLORS["bg_primary"], font=("Segoe UI", 9, "bold"), command=self._start_simulation)
        self.btn_start.pack(side=tk.LEFT, padx=10, pady=8)

        self.btn_stop = tk.Button(controls, text="⏹ Arrêter", bg=COLORS["accent_red"], fg=COLORS["bg_primary"], font=("Segoe UI", 9, "bold"), command=self._stop_simulation, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5, pady=8)

        tk.Label(controls, text="Vitesse:", bg=COLORS["bg_secondary"], fg=COLORS["text_primary"]).pack(side=tk.LEFT, padx=(20, 5))
        tk.Scale(controls, from_=0.1, to=3.0, resolution=0.1, orient=tk.HORIZONTAL, variable=self.animation_speed, bg=COLORS["bg_secondary"], fg=COLORS["accent_cyan"], highlightthickness=0, length=120).pack(side=tk.LEFT, padx=5)

        tk.Label(controls, text="Débit:", bg=COLORS["bg_secondary"], fg=COLORS["text_primary"]).pack(side=tk.LEFT, padx=(20, 5))
        tk.Scale(controls, from_=1, to=20, resolution=1, orient=tk.HORIZONTAL, variable=self.packet_rate, bg=COLORS["bg_secondary"], fg=COLORS["accent_yellow"], highlightthickness=0, length=120).pack(side=tk.LEFT, padx=5)

        tk.Checkbutton(controls, text="Grille", variable=self.show_grid, bg=COLORS["bg_secondary"], fg=COLORS["text_primary"], selectcolor=COLORS["bg_primary"]).pack(side=tk.LEFT, padx=15)
        tk.Checkbutton(controls, text="Auto-scroll", variable=self.auto_scroll, bg=COLORS["bg_secondary"], fg=COLORS["text_primary"], selectcolor=COLORS["bg_primary"]).pack(side=tk.LEFT, padx=5)

    # --------------------------------------------------------------------------
    #  PANNEAU D'ONGLETS
    # --------------------------------------------------------------------------
    def _build_tabs_panel(self, parent):
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tab_capture = tk.Frame(self.notebook, bg=COLORS["bg_secondary"])
        self.tab_nodes = tk.Frame(self.notebook, bg=COLORS["bg_secondary"])
        self.tab_stats = tk.Frame(self.notebook, bg=COLORS["bg_secondary"])
        self.tab_commands = tk.Frame(self.notebook, bg=COLORS["bg_secondary"])
        self.tab_definitions = tk.Frame(self.notebook, bg=COLORS["bg_secondary"])
        self.tab_terminal = tk.Frame(self.notebook, bg=COLORS["bg_secondary"])
        self.tab_emergency = tk.Frame(self.notebook, bg=COLORS["bg_secondary"])

        self.notebook.add(self.tab_capture, text="📡 Capture")
        self.notebook.add(self.tab_nodes, text="🖥 Nœuds")
        self.notebook.add(self.tab_stats, text="📊 Stats")
        self.notebook.add(self.tab_commands, text="🛠 Commandes")
        self.notebook.add(self.tab_definitions, text="📚 Définitions")
        self.notebook.add(self.tab_terminal, text="💻 Terminal")
        self.notebook.add(self.tab_emergency, text="🌍 Urgence")

        self._build_capture_tab(self.tab_capture)
        self._build_nodes_tab(self.tab_nodes)
        self._build_stats_tab(self.tab_stats)
        self._build_commands_tab(self.tab_commands)
        self._build_definitions_tab(self.tab_definitions)
        self._build_terminal_tab(self.tab_terminal)
        self._build_emergency_tab(self.tab_emergency)

    # --------------------------------------------------------------------------
    #  ONGLET CAPTURE
    # --------------------------------------------------------------------------
    def _build_capture_tab(self, parent):
        toolbar = tk.Frame(parent, bg=COLORS["bg_tertiary"])
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(toolbar, text="🗑 Effacer", bg=COLORS["accent_red"], fg=COLORS["bg_primary"], command=self._clear_capture).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="💾 Exporter TXT", bg=COLORS["accent_cyan"], fg=COLORS["bg_primary"], command=self._export_capture).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="📤 Exporter JSON", bg=COLORS["accent_yellow"], fg=COLORS["bg_primary"], command=self._export_packets).pack(side=tk.LEFT, padx=5)

        self.capture_text = scrolledtext.ScrolledText(parent, bg=COLORS["bg_primary"], fg=COLORS["text_primary"], font=self.font_mono, state=tk.DISABLED)
        self.capture_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.capture_text.tag_config("rs", foreground=COLORS["packet_rs"])
        self.capture_text.tag_config("ra", foreground=COLORS["packet_ra"])
        self.capture_text.tag_config("ns", foreground=COLORS["packet_ns"])
        self.capture_text.tag_config("na", foreground=COLORS["packet_na"])
        self.capture_text.tag_config("redirect", foreground=COLORS["packet_redirect"])

    # --------------------------------------------------------------------------
    #  ONGLET NŒUDS
    # --------------------------------------------------------------------------
    def _build_nodes_tab(self, parent):
        columns = ("ID", "Type", "IPv6", "MAC", "État", "Voisins")
        self.tree_nodes = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.tree_nodes.heading(col, text=col)
            self.tree_nodes.column(col, width=120)
        self.tree_nodes.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tree_nodes.bind("<<TreeviewSelect>>", self._on_node_select)

        self.node_detail_label = tk.Label(parent, text="Sélectionnez un nœud pour voir les détails.", bg=COLORS["bg_secondary"], fg=COLORS["accent_cyan"], font=self.font_mono, justify=tk.LEFT, anchor=tk.NW)
        self.node_detail_label.pack(fill=tk.X, padx=5, pady=5)

    # --------------------------------------------------------------------------
    #  ONGLET STATISTIQUES
    # --------------------------------------------------------------------------
    def _build_stats_tab(self, parent):
        self.stats_text = scrolledtext.ScrolledText(parent, bg=COLORS["bg_primary"], fg=COLORS["text_primary"], font=self.font_mono, state=tk.DISABLED)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # --------------------------------------------------------------------------
    #  ONGLET COMMANDES
    # --------------------------------------------------------------------------
    def _build_commands_tab(self, parent):
        tk.Label(parent, text="Sélectionnez une commande réseau à exécuter :", bg=COLORS["bg_secondary"], fg=COLORS["text_primary"], font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=10, pady=10)

        self.command_var = tk.StringVar()
        command_list = list(COMMANDS_BY_OS[self.current_os].keys())
        self.combo_commands = ttk.Combobox(parent, textvariable=self.command_var, values=command_list, state="readonly", width=50)
        self.combo_commands.pack(anchor=tk.W, padx=10, pady=5)
        if command_list:
            self.combo_commands.current(0)

        tk.Button(parent, text="▶ Exécuter", bg=COLORS["accent_green"], fg=COLORS["bg_primary"], font=("Segoe UI", 9, "bold"), command=self._run_selected_command).pack(anchor=tk.W, padx=10, pady=5)
        tk.Button(parent, text="📋 Copier la commande", bg=COLORS["accent_cyan"], fg=COLORS["bg_primary"], command=self._copy_selected_command).pack(anchor=tk.W, padx=10, pady=5)

        self.command_output = scrolledtext.ScrolledText(parent, bg=COLORS["bg_primary"], fg=COLORS["accent_yellow"], font=self.font_mono, height=20, state=tk.DISABLED)
        self.command_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # --------------------------------------------------------------------------
    #  ONGLET DÉFINITIONS
    # --------------------------------------------------------------------------
    def _build_definitions_tab(self, parent):
        self.def_tree = ttk.Treeview(parent, columns=("Terme",), show="tree", selectmode="browse")
        self.def_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.def_tree.column("#0", width=300)

        self.def_detail = scrolledtext.ScrolledText(parent, bg=COLORS["bg_primary"], fg=COLORS["text_primary"], font=self.font_mono, wrap=tk.WORD, state=tk.DISABLED)
        self.def_detail.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        for term in sorted(NDP_DEFINITIONS.keys()):
            self.def_tree.insert("", tk.END, text=term, values=(term,))
        self.def_tree.bind("<<TreeviewSelect>>", self._on_definition_select)

    # --------------------------------------------------------------------------
    #  ONGLET TERMINAL
    # --------------------------------------------------------------------------
    def _build_terminal_tab(self, parent):
        self.terminal = scrolledtext.ScrolledText(parent, bg=COLORS["bg_primary"], fg=COLORS["accent_green"], font=self.font_mono, insertbackground=COLORS["accent_cyan"], wrap=tk.WORD)
        self.terminal.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.terminal.insert(tk.END, f"{APP_TITLE} v{APP_VERSION} Terminal intégré\n")
        self.terminal.insert(tk.END, f"Système détecté : {self.current_os}\n")
        self.terminal.insert(tk.END, "Tapez 'help' pour la liste des commandes.\n\n> ")
        self.terminal.bind("<Return>", self._on_terminal_command)
        self.terminal.bind("<Key>", lambda e: "break" if int(self.terminal.index(tk.INSERT).split(".")[0]) < int(self.terminal.index(tk.END).split(".")[0]) - 1 else None)

    # --------------------------------------------------------------------------
    #  ONGLET URGENCE
    # --------------------------------------------------------------------------
    def _build_emergency_tab(self, parent):
        tk.Label(parent, text="🌍 Numéros d'urgence par pays", bg=COLORS["bg_secondary"], fg=COLORS["accent_cyan"], font=self.font_title).pack(pady=10)
        self.emergency_text = scrolledtext.ScrolledText(parent, bg=COLORS["bg_primary"], fg=COLORS["text_primary"], font=self.font_mono, state=tk.DISABLED)
        self.emergency_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self._refresh_emergency_tab()

    def _refresh_emergency_tab(self):
        lines = ["PAYS                 POLICE   POMPIERS  SAMU     INTERNATIONAL", "=" * 70]
        for country, nums in sorted(EMERGENCY_NUMBERS.items()):
            lines.append(f"{country:20s} {nums['police']:8s} {nums['pompiers']:9s} {nums['samu']:8s} {nums['international']:13s}")
        self.emergency_text.config(state=tk.NORMAL)
        self.emergency_text.delete(1.0, tk.END)
        self.emergency_text.insert(tk.END, "\n".join(lines))
        self.emergency_text.config(state=tk.DISABLED)

    # ==============================================================================
    #  SECTION 7 : LOGIQUE DE SIMULATION
    # ==============================================================================

    def _initialize_default_network(self):
        """Crée un réseau par défaut avec routeur, passerelle et hôtes."""
        self.nodes.clear()
        self.packets.clear()
        self.packet_counter = 0
        self.animations.clear()

        router = NetworkNode(
            node_id="R1",
            ip=generate_ipv6("2001:db8:1", "1"),
            mac=generate_mac(),
            x=0.0, y=0.0, z=0.0,
            node_type="router",
        )
        self.nodes["R1"] = router

        gateway = NetworkNode(
            node_id="GW",
            ip=generate_ipv6("2001:db8:0", "1"),
            mac=generate_mac(),
            x=-250.0, y=-120.0, z=80.0,
            node_type="gateway",
        )
        self.nodes["GW"] = gateway

        positions = [
            (180, 140, 60), (-160, 130, -70), (140, -150, 90),
            (-140, -140, -50), (220, 0, -100), (0, 200, 40), (-220, 20, 120),
        ]
        for i, (x, y, z) in enumerate(positions, start=1):
            host = NetworkNode(
                node_id=f"H{i}",
                ip=generate_ipv6("2001:db8:1", f"{i+10}"),
                mac=generate_mac(),
                x=x, y=y, z=z,
                node_type="host",
                neighbors=["R1"],
            )
            self.nodes[host.node_id] = host

        router.neighbors = [n for n in self.nodes if n != "R1"]
        gateway.neighbors = ["R1"]

        self._log_terminal("Réseau initialisé : 1 routeur, 1 passerelle, 7 hôtes.")
        self._refresh_nodes_tree()
        self._update_stats()

    def _start_simulation(self):
        self.simulation_running = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status_var.set("Simulation EN COURS")
        self._log_terminal("Simulation démarrée.")

    def _stop_simulation(self):
        self.simulation_running = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status_var.set("Simulation en PAUSE")
        self._log_terminal("Simulation mise en pause.")

    def _reset_simulation(self):
        self._stop_simulation()
        self._initialize_default_network()
        self._clear_capture()
        self._draw_scene()

    def _simulation_loop(self):
        """Boucle de génération de paquets en arrière-plan."""
        while True:
            if self.simulation_running and self.nodes:
                rate = max(1, self.packet_rate.get())
                if random.random() < (rate / 10.0):
                    self._generate_random_packet()
            time.sleep(0.1)

    def _generate_random_packet(self):
        """Génère un paquet NDP aléatoire entre deux nœuds."""
        node_ids = list(self.nodes.keys())
        if len(node_ids) < 2:
            return

        src_id = random.choice(node_ids)
        dst_id = random.choice([n for n in node_ids if n != src_id])
        src = self.nodes[src_id]
        dst = self.nodes[dst_id]

        msg_type = random.choices(
            list(NDP_MESSAGE_TYPES.keys()),
            weights=[10, 25, 35, 25, 5],
            k=1
        )[0]

        options = []
        if "Solicitation" in msg_type or "Advertisement" in msg_type:
            options.append((1, src.mac))
        if "Neighbor" in msg_type:
            options.append((2, dst.mac))
        if msg_type == "Router Advertisement (RA)":
            options.append((3, "2001:db8:1::/64"))
            options.append((5, "1500"))

        self.packet_counter += 1
        packet = NdpPacket(
            msg_type=msg_type,
            source_ip=src.ip,
            target_ip=dst.ip,
            source_mac=src.mac,
            target_mac=dst.mac,
            options=options,
            sequence=self.packet_counter,
        )

        self.packets.append(packet)
        self._log_capture(packet)
        self._spawn_animation(src, dst, msg_type)
        self._update_stats()
        self._refresh_nodes_tree()

    def _spawn_animation(self, src: NetworkNode, dst: NetworkNode, msg_type: str):
        """Crée une animation de paquet entre deux nœuds."""
        color_key = NDP_MESSAGE_TYPES.get(msg_type, {}).get("color", "accent_cyan")
        color = COLORS[color_key]
        self.animations.append({
            "src": src,
            "dst": dst,
            "progress": 0.0,
            "color": color,
            "type": msg_type,
            "speed": 0.02 * self.animation_speed.get(),
        })

    # ==============================================================================
    #  SECTION 8 : RENDU 3D SUR CANVAS TKINTER
    # ==============================================================================

    def _project_3d(self, x: float, y: float, z: float) -> Tuple[int, int, float]:
        """Projette un point 3D vers le canvas 2D avec rotation."""
        width = self.canvas_3d.winfo_width()
        height = self.canvas_3d.winfo_height()
        cx, cy = width // 2, height // 2
        scale = min(width, height) / 700.0

        angle = self.rotation_angle
        cos_a, sin_a = math.cos(angle), math.sin(angle)

        xr = x * cos_a - z * sin_a
        zr = x * sin_a + z * cos_a

        fov = 400.0
        if zr + fov <= 0:
            zr = -fov + 1
        factor = fov / (zr + fov)
        px = int(cx + xr * factor * scale)
        py = int(cy + y * factor * scale)
        return px, py, factor

    def _draw_scene(self):
        """Dessine la scène 3D (grille, liens, nœuds, paquets)."""
        self.canvas_3d.delete("all")
        width = self.canvas_3d.winfo_width()
        height = self.canvas_3d.winfo_height()
        if width < 100 or height < 100:
            self.root.after(100, self._draw_scene)
            return

        if self.show_grid.get():
            self._draw_grid()

        for node in self.nodes.values():
            for neighbor_id in node.neighbors:
                if neighbor_id in self.nodes:
                    neighbor = self.nodes[neighbor_id]
                    x1, y1, _ = self._project_3d(node.x, node.y, node.z)
                    x2, y2, _ = self._project_3d(neighbor.x, neighbor.y, neighbor.z)
                    self.canvas_3d.create_line(x1, y1, x2, y2, fill=COLORS["grid"], width=1)

        for node in self.nodes.values():
            px, py, factor = self._project_3d(node.x, node.y, node.z)
            radius = max(6, int(14 * factor))
            if node.node_type == "router":
                color = COLORS["accent_cyan"]
            elif node.node_type == "gateway":
                color = COLORS["accent_magenta"]
            else:
                color = COLORS["accent_green"]
            self.canvas_3d.create_oval(px - radius, py - radius, px + radius, py + radius, fill=color, outline=COLORS["text_primary"], width=2)
            self.canvas_3d.create_text(px, py - radius - 12, text=node.node_id, fill=COLORS["text_primary"], font=("Segoe UI", 9, "bold"))
            self.canvas_3d.create_text(px, py + radius + 12, text=node.ip, fill=COLORS["text_secondary"], font=("Segoe UI", 7))

        for anim in self.animations:
            src = anim["src"]
            dst = anim["dst"]
            p = anim["progress"]
            x = src.x + (dst.x - src.x) * p
            y = src.y + (dst.y - src.y) * p
            z = src.z + (dst.z - src.z) * p
            px, py, factor = self._project_3d(x, y, z)
            radius = max(4, int(8 * factor))
            self.canvas_3d.create_oval(px - radius, py - radius, px + radius, py + radius, fill=anim["color"], outline=COLORS["bg_primary"])

    def _draw_grid(self):
        """Dessine une grille de référence 3D."""
        size = 300
        step = 60
        for i in range(-size, size + 1, step):
            x1, y1, _ = self._project_3d(i, 200, -size)
            x2, y2, _ = self._project_3d(i, 200, size)
            self.canvas_3d.create_line(x1, y1, x2, y2, fill=COLORS["grid"], width=1)
            x1, y1, _ = self._project_3d(-size, 200, i)
            x2, y2, _ = self._project_3d(size, 200, i)
            self.canvas_3d.create_line(x1, y1, x2, y2, fill=COLORS["grid"], width=1)

    def _animate(self):
        """Met à jour l'animation frame par frame."""
        self.rotation_angle += 0.003 * self.animation_speed.get()

        to_remove = []
        for anim in self.animations:
            anim["progress"] += anim["speed"]
            if anim["progress"] >= 1.0:
                to_remove.append(anim)
        for anim in to_remove:
            self.animations.remove(anim)

        self._draw_scene()
        self.root.after(30, self._animate)

    def _on_canvas_click(self, event):
        """Détecte le clic sur un nœud du canvas."""
        for node in self.nodes.values():
            px, py, factor = self._project_3d(node.x, node.y, node.z)
            radius = max(10, int(18 * factor))
            if (event.x - px) ** 2 + (event.y - py) ** 2 <= radius ** 2:
                self.selected_node_id = node.node_id
                self._show_node_details(node)
                self.notebook.select(self.tab_nodes)
                break

    # ==============================================================================
    #  SECTION 9 : GESTION DE L'AFFICHAGE
    # ==============================================================================

    def _log_capture(self, packet: NdpPacket):
        """Ajoute un paquet au journal de capture."""
        self.capture_text.config(state=tk.NORMAL)
        tag = "rs"
        if "Router Advertisement" in packet.msg_type:
            tag = "ra"
        elif "Neighbor Solicitation" in packet.msg_type:
            tag = "ns"
        elif "Neighbor Advertisement" in packet.msg_type:
            tag = "na"
        elif "Redirect" in packet.msg_type:
            tag = "redirect"

        line = format_packet_log(packet) + "\n"
        self.capture_text.insert(tk.END, line, tag)
        if self.auto_scroll.get():
            self.capture_text.see(tk.END)
        self.capture_text.config(state=tk.DISABLED)

    def _clear_capture(self):
        self.capture_text.config(state=tk.NORMAL)
        self.capture_text.delete(1.0, tk.END)
        self.capture_text.config(state=tk.DISABLED)

    def _refresh_nodes_tree(self):
        """Rafraîchit la liste des nœuds."""
        for item in self.tree_nodes.get_children():
            self.tree_nodes.delete(item)
        for node in self.nodes.values():
            state = "En ligne" if node.is_online else "Hors ligne"
            self.tree_nodes.insert("", tk.END, values=(
                node.node_id,
                node.node_type.upper(),
                node.ip,
                node.mac,
                state,
                ", ".join(node.neighbors),
            ))

    def _on_node_select(self, event):
        selection = self.tree_nodes.selection()
        if selection:
            item = self.tree_nodes.item(selection[0])
            node_id = item["values"][0]
            if node_id in self.nodes:
                self.selected_node_id = node_id
                self._show_node_details(self.nodes[node_id])

    def _show_node_details(self, node: NetworkNode):
        text = (
            f"ID          : {node.node_id}\n"
            f"Type        : {node.node_type.upper()}\n"
            f"IPv6        : {node.ip}\n"
            f"MAC         : {node.mac}\n"
            f"Position 3D : ({node.x:.1f}, {node.y:.1f}, {node.z:.1f})\n"
            f"État        : {'En ligne' if node.is_online else 'Hors ligne'}\n"
            f"Voisins     : {', '.join(node.neighbors)}\n"
            f"Multicast   : {solicited_node_multicast(node.ip)}\n"
            f"Dernière vue: {datetime.datetime.fromtimestamp(node.last_seen).strftime('%H:%M:%S')}"
        )
        self.node_detail_label.config(text=text)

    def _update_stats(self):
        """Met à jour l'onglet statistiques."""
        counts = Counter([p.msg_type for p in self.packets])
        total = len(self.packets)

        lines = []
        lines.append("=" * 60)
        lines.append(" STATISTIQUES NDP - Capture en cours")
        lines.append("=" * 60)
        lines.append(f"Total de paquets capturés : {total}")
        lines.append(f"Nœuds simulés             : {len(self.nodes)}")
        lines.append(f"Paquets en vol            : {len(self.animations)}")
        lines.append("")
        lines.append("Répartition par type de message :")
        for name, info in NDP_MESSAGE_TYPES.items():
            c = counts.get(name, 0)
            pct = (c / total * 100) if total > 0 else 0
            bar = "█" * int(pct / 5)
            lines.append(f"  {info['code']:3d} {name:35s} : {c:4d} ({pct:5.1f}%) {bar}")
        lines.append("")
        lines.append("Statistiques mondiales IPv6 / NDP :")
        for key, value in GLOBAL_IPV6_STATS.items():
            lines.append(f"  • {key}: {value}")
        lines.append("")
        lines.append(f"Dernière mise à jour : {datetime.datetime.now().strftime('%H:%M:%S')}")

        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, "\n".join(lines))
        self.stats_text.config(state=tk.DISABLED)

    def _on_definition_select(self, event):
        selection = self.def_tree.selection()
        if selection:
            term = self.def_tree.item(selection[0], "text")
            data = NDP_DEFINITIONS.get(term, {})
            self.def_detail.config(state=tk.NORMAL)
            self.def_detail.delete(1.0, tk.END)
            self.def_detail.insert(tk.END, f"{term}\n", "title")
            self.def_detail.insert(tk.END, f"{'=' * len(term)}\n\n", "title")
            self.def_detail.insert(tk.END, f"Définition :\n{data.get('definition', 'Non disponible')}\n\n")
            self.def_detail.insert(tk.END, f"À quoi ça sert ?\n{data.get('usage', 'Non disponible')}\n\n")
            self.def_detail.insert(tk.END, f"Couche / Protocole : {data.get('couche', 'N/A')}\n")
            self.def_detail.insert(tk.END, f"Référence RFC     : {data.get('rfc', 'N/A')}\n")
            self.def_detail.tag_config("title", foreground=COLORS["accent_cyan"], font=("Segoe UI", 12, "bold"))
            self.def_detail.config(state=tk.DISABLED)

    # ==============================================================================
    #  SECTION 10 : FONCTIONNALITÉS AVANCÉES
    # ==============================================================================

    def _open_custom_packet_dialog(self):
        """Ouvre une fenêtre pour générer un paquet personnalisé."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Générer un paquet NDP personnalisé")
        dialog.configure(bg=COLORS["bg_secondary"])
        dialog.geometry("500x500")

        tk.Label(dialog, text="Type de message :", bg=COLORS["bg_secondary"], fg=COLORS["text_primary"]).pack(anchor=tk.W, padx=10, pady=5)
        msg_var = tk.StringVar()
        combo = ttk.Combobox(dialog, textvariable=msg_var, values=list(NDP_MESSAGE_TYPES.keys()), state="readonly", width=45)
        combo.pack(anchor=tk.W, padx=10)
        combo.current(2)

        tk.Label(dialog, text="Source (nœud) :", bg=COLORS["bg_secondary"], fg=COLORS["text_primary"]).pack(anchor=tk.W, padx=10, pady=5)
        src_var = tk.StringVar()
        src_combo = ttk.Combobox(dialog, textvariable=src_var, values=list(self.nodes.keys()), state="readonly", width=45)
        src_combo.pack(anchor=tk.W, padx=10)
        if self.nodes:
            src_combo.current(0)

        tk.Label(dialog, text="Destination (nœud) :", bg=COLORS["bg_secondary"], fg=COLORS["text_primary"]).pack(anchor=tk.W, padx=10, pady=5)
        dst_var = tk.StringVar()
        dst_combo = ttk.Combobox(dialog, textvariable=dst_var, values=list(self.nodes.keys()), state="readonly", width=45)
        dst_combo.pack(anchor=tk.W, padx=10)
        if len(self.nodes) > 1:
            dst_combo.current(1)

        def send_custom():
            msg = msg_var.get()
            src_id = src_var.get()
            dst_id = dst_var.get()
            if not msg or not src_id or not dst_id or src_id == dst_id:
                messagebox.showerror("Erreur", "Sélection invalide.", parent=dialog)
                return
            src = self.nodes[src_id]
            dst = self.nodes[dst_id]
            self.packet_counter += 1
            packet = NdpPacket(
                msg_type=msg,
                source_ip=src.ip,
                target_ip=dst.ip,
                source_mac=src.mac,
                target_mac=dst.mac,
                sequence=self.packet_counter,
                options=[(1, src.mac), (2, dst.mac)],
            )
            self.packets.append(packet)
            self._log_capture(packet)
            self._spawn_animation(src, dst, msg)
            self._update_stats()
            dialog.destroy()

        tk.Button(dialog, text="Envoyer le paquet", bg=COLORS["accent_green"], fg=COLORS["bg_primary"], font=("Segoe UI", 10, "bold"), command=send_custom).pack(pady=20)

    def _open_command_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Exécuter une commande")
        dialog.configure(bg=COLORS["bg_secondary"])
        dialog.geometry("600x200")
        tk.Label(dialog, text="Commande :", bg=COLORS["bg_secondary"], fg=COLORS["text_primary"]).pack(anchor=tk.W, padx=10, pady=5)
        cmd_entry = tk.Entry(dialog, width=70, bg=COLORS["bg_primary"], fg=COLORS["accent_green"], insertbackground=COLORS["accent_cyan"])
        cmd_entry.pack(anchor=tk.W, padx=10)

        def run():
            cmd = cmd_entry.get().strip()
            if cmd:
                self._execute_command(cmd)
                dialog.destroy()

        tk.Button(dialog, text="Exécuter", bg=COLORS["accent_green"], fg=COLORS["bg_primary"], command=run).pack(pady=10)

    def _run_selected_command(self):
        name = self.command_var.get()
        if not name:
            return
        cmd = COMMANDS_BY_OS[self.current_os].get(name)
        if cmd:
            self._execute_command(cmd)

    def _copy_selected_command(self):
        name = self.command_var.get()
        if not name:
            return
        cmd = COMMANDS_BY_OS[self.current_os].get(name)
        if cmd:
            self.root.clipboard_clear()
            self.root.clipboard_append(cmd)
            self.status_var.set(f"Commande copiée : {cmd}")

    def _execute_command(self, command: str):
        """Exécute une commande shell et affiche le résultat."""
        self.command_output.config(state=tk.NORMAL)
        self.command_output.insert(tk.END, f"\n$ {command}\n")
        self.command_output.config(state=tk.DISABLED)
        self._log_terminal(f"Exécution : {command}")

        def run():
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
                output = result.stdout + result.stderr
                if not output.strip():
                    output = "(Aucune sortie)"
            except Exception as e:
                output = f"Erreur : {str(e)}"
            self.root.after(0, lambda: self._append_command_output(output))

        threading.Thread(target=run, daemon=True).start()

    def _check_ipv6_connectivity(self):
        target = "2001:4860:4860::8888"
        self._execute_command(f"ping -6 -n 4 {target}" if self.current_os == "Windows" else f"ping6 -c 4 {target}")

    def _open_emergency_map(self):
        self.notebook.select(self.tab_emergency)

    def _export_packets(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if path:
            data = [p.to_dict() for p in self.packets]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.status_var.set(f"Paquets exportés vers {path}")

    def _export_capture(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if path:
            self.capture_text.config(state=tk.NORMAL)
            content = self.capture_text.get(1.0, tk.END)
            self.capture_text.config(state=tk.DISABLED)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.status_var.set(f"Capture exportée vers {path}")

    def _show_about(self):
        messagebox.showinfo(
            "À propos",
            f"{APP_TITLE}\nVersion {APP_VERSION}\nCréé par {APP_AUTHOR}\n\n"
            "Outil pédagogique avancé de visualisation et diagnostic du protocole NDP (IPv6).\n"
            "Inclut simulation de paquets, rendu 3D, capture, statistiques et commandes réseau."
        )

    # ==============================================================================
    #  SECTION 11 : TERMINAL INTÉGRÉ
    # ==============================================================================

    def _log_terminal(self, message: str):
        self.terminal.config(state=tk.NORMAL)
        self.terminal.insert(tk.END, f"{message}\n")
        self.terminal.see(tk.END)
        self.terminal.config(state=tk.DISABLED)

    def _on_terminal_command(self, event):
        self.terminal.config(state=tk.NORMAL)
        line = self.terminal.get("insert linestart", "insert lineend")
        cmd = line.replace("> ", "").strip()
        self.terminal.insert(tk.END, "\n")

        if cmd.lower() == "help":
            self.terminal.insert(tk.END, "Commandes disponibles :\n")
            self.terminal.insert(tk.END, "  help        - Afficher cette aide\n")
            self.terminal.insert(tk.END, "  clear       - Effacer le terminal\n")
            self.terminal.insert(tk.END, "  nodes       - Lister les nœuds\n")
            self.terminal.insert(tk.END, "  packets     - Nombre de paquets capturés\n")
            self.terminal.insert(tk.END, "  start       - Démarrer la simulation\n")
            self.terminal.insert(tk.END, "  stop        - Arrêter la simulation\n")
            self.terminal.insert(tk.END, "  reset       - Réinitialiser le réseau\n")
            self.terminal.insert(tk.END, "  stats       - Afficher les statistiques\n")
            self.terminal.insert(tk.END, "  ping6 <ip>  - Lancer un ping IPv6\n")
            self.terminal.insert(tk.END, "  exit        - Quitter l'application\n")
        elif cmd.lower() == "clear":
            self.terminal.delete(1.0, tk.END)
            self.terminal.insert(tk.END, f"{APP_TITLE} v{APP_VERSION} Terminal intégré\n> ")
            self.terminal.config(state=tk.DISABLED)
            return "break"
        elif cmd.lower() == "nodes":
            for n in self.nodes.values():
                self.terminal.insert(tk.END, f"  {n.node_id} {n.ip} {n.mac} {n.node_type}\n")
        elif cmd.lower() == "packets":
            self.terminal.insert(tk.END, f"Total de paquets capturés : {len(self.packets)}\n")
        elif cmd.lower() == "start":
            self._start_simulation()
        elif cmd.lower() == "stop":
            self._stop_simulation()
        elif cmd.lower() == "reset":
            self._reset_simulation()
        elif cmd.lower() == "stats":
            self.terminal.insert(tk.END, f"Paquets : {len(self.packets)} | Nœuds : {len(self.nodes)} | En vol : {len(self.animations)}\n")
        elif cmd.lower().startswith("ping6 "):
            target = cmd[6:].strip()
            self._execute_command(f"ping -6 -n 4 {target}" if self.current_os == "Windows" else f"ping6 -c 4 {target}")
        elif cmd.lower() == "exit":
            self.root.quit()
        elif cmd:
            self.terminal.insert(tk.END, f"Commande inconnue : {cmd}\n")

        self.terminal.insert(tk.END, "> ")
        self.terminal.see(tk.END)
        self.terminal.config(state=tk.DISABLED)
        return "break"


# ==============================================================================
#  SECTION 12 : POINT D'ENTRÉE
# ==============================================================================

def main():
    root = tk.Tk()
    try:
        app = NdpAdvancedToolkit(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Erreur fatale", f"Impossible de démarrer l'application :\n{e}")
        raise


if __name__ == "__main__":
    main()

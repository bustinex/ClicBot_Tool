# -*- coding: utf-8 -*-
"""
ClicBot Dev Tools 1.0 - DYNAMIC & INTEGRATED + WIZARD + OPTIMIZED JOYSTICK + SPEED CONTROL
- Core v3 (Connessione, ZIP, JSON, WebSocket, Log).
- Assembly Mode (Entrata/Uscita).
- Dynamic Joystick: Calcola i pacchetti in base alla configurazione reale del robot.
- Programming Wizard: Popup interattivo per la calibrazione.
- OPTIMIZATION: Invia pacchetti drive solo se necessario (Delta check & Deadzone).
- NEW: Decoder Telemetria 0x03F3.
- NEW: Slider Velocità per regolare la potenza dei motori.
"""

import socket
import json
import threading
import time
import struct
import random
import queue
import math
import os
import sys
import subprocess
import datetime
import uuid
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import XInput
except ImportError:
    XInput = None
    print("[ERRORE] Libreria 'XInput-Python' non trovata.")
    print("Installa con: pip install XInput-Python")
    
# --- optional websocket bridge (PC -> viewer_hex.html) ---
try:
    import asyncio
    import websockets  # type: ignore
except Exception:
    asyncio = None
    websockets = None

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    serialization = None
    Ed25519PublicKey = None


HELLO8 = bytes.fromhex("e3 03 00 00 00 00 00 00")
LICENSE_TOKEN_PREFIX = "CB1"
# Default public key (Ed25519 raw, 32 bytes). Can be overridden by license_public.pem.
DEFAULT_LICENSE_PUBKEY_HEX = "74f75a21d03fbca2ad633ccb568bcbf2f97204655b9c2c7db2394c96af1768a4"


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))

# --- 03E9 -> JSON (STRUCTURE) conversion ---
ANGLE_SCALE = 360.0 / 4096.0
TYPE_NAMES = {1: "Sfera", 2: "Scheletro", 3: "Ruota", 4: "Sensore", 5: "Piede", 6: "Pinza", 7: "Ventosa"}

def _fmt_addr(p_index: int, p_interface: int) -> str:
    return f"{p_index:02X}{p_interface:02X}".upper()

def _fmt_addr_bytes(b: bytes) -> str:
    if not b or len(b) < 2: return ""
    if b[0] == 0 and b[1] == 0: return ""
    return f"{b[0]:02X}{b[1]:02X}".upper()

def parse_03e9_payload_to_structure(payload: bytes) -> dict:
    nodes = [{"address": "", "angle": 0.0, "circularInfo": [], "direction": 0, "mDepth": 0, "mIndex": 0, "mInterface": 0, "matchType": 0, "pIndex": 0, "pInformation": 0, "pInterface": 0, "parallel": False, "type": 0}]
    if not payload: return {"STRUCTURE": nodes}
    rec_size = 28
    if len(payload) % rec_size != 0:
        for skip in (1, 2, 3, 4):
            if len(payload) > skip and (len(payload) - skip) % rec_size == 0:
                payload = payload[skip:]
                break
    for off in range(0, len(payload), rec_size):
        rec = payload[off : off + rec_size]
        if len(rec) < rec_size: break
        m_index, m_depth, m_interface, mod_type = rec[0], rec[1], rec[2], rec[3]
        parallel, direction = bool(rec[5]), rec[6]
        angle = round(int.from_bytes(rec[7:9], "little", signed=False) * ANGLE_SCALE, 6)
        p_index, p_interface = rec[9], rec[10]
        addr = _fmt_addr_bytes(rec[13:15]) or _fmt_addr_bytes(rec[11:13])
        nodes.append({"address": addr or _fmt_addr(p_index, p_interface), "angle": angle, "circularInfo": [], "direction": int(direction), "mDepth": int(m_depth), "mIndex": int(m_index), "mInterface": int(m_interface), "matchType": 0, "pIndex": int(p_index), "pInformation": 0, "pInterface": int(p_interface), "parallel": bool(parallel), "type": int(mod_type)})
    nodes_sorted = [nodes[0]] + sorted(nodes[1:], key=lambda n: (n["mDepth"], n["mIndex"]))
    return {"STRUCTURE": nodes_sorted}

def parse_03eb_payload_to_updates(payload: bytes):
    out = []
    if not payload: return out
    data = payload
    if (len(data) % 3) != 0 and len(data) >= 4 and ((len(data) - 4) % 3) == 0: data = data[4:]
    if (len(data) % 3) != 0: data = data[: (len(data) // 3) * 3]
    for off in range(0, len(data) - 2, 3):
        m_index = data[off]
        raw = int.from_bytes(data[off + 1 : off + 3], "little", signed=False)
        deg = round(raw * ANGLE_SCALE, 6)
        out.append((int(m_index), int(raw), float(deg)))
    return out

# --- Parser per F3 (Telemetria Movimento) ---
def parse_03f3_payload(payload: bytes):
    """
    Decodifica il pacchetto F3 (Feedback movimento calibrazione).
    Formato Ruote: [ID] [DIR 0/1] [SPEED 0-255]
    """
    out = []
    if not payload: return out
    data = payload
    
    # Legge a blocchi di 3 byte: [ID, High(Sign), Low(Val)]
    for off in range(0, len(data) - 2, 3):
        m_index = data[off]
        sign_byte = data[off+1] # 00 = +, 01 = -
        val_byte = data[off+2]  # Magnitudine
        
        # Applica il segno
        final_val = val_byte if sign_byte == 0 else -val_byte
        out.append((m_index, final_val))
    return out

class WsBridge:
    def __init__(self, host="127.0.0.1", port=8787, log=None):
        self.host = host
        self.port = int(port)
        self.log = log or (lambda s: None)
        self._thread = None
        self._loop = None
        self._server = None
        self._clients = set()
        self._q = None
        self._running = False
    def is_available(self): return websockets is not None and asyncio is not None
    def start(self):
        if self._running: return
        if not self.is_available():
            self.log("[WS] 'websockets' non disponibile.\n")
            return
        import threading
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.log(f"[WS] Bridge attivo su ws://{self.host}:{self.port}\n")
    def stop(self):
        if not self._running: return
        self._running = False
        if self._loop:
            try: self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception: pass
        self.log("[WS] Bridge fermato\n")
    def publish(self, hex_str: str):
        if not self._running or not self._loop or not self._q: return
        try: self._loop.call_soon_threadsafe(self._q.put_nowait, hex_str)
        except Exception: pass
    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._q = asyncio.Queue()
        async def handler(ws):
            self._clients.add(ws)
            try:
                await ws.send("HELLO")
                async for _ in ws: pass
            except Exception: pass
            finally: self._clients.discard(ws)
        async def broadcaster():
            while True:
                msg = await self._q.get()
                dead = []
                for c in list(self._clients):
                    try: await c.send(msg)
                    except Exception: dead.append(c)
                for c in dead: self._clients.discard(c)
        async def main():
            self._server = await websockets.serve(handler, self.host, self.port)
            self._loop.create_task(broadcaster())
        try:
            self._loop.run_until_complete(main())
            self._loop.run_forever()
        except Exception: pass
        finally:
            try:
                if self._server:
                    self._server.close()
                    self._loop.run_until_complete(self._server.wait_closed())
            except Exception: pass
            try:
                for c in list(self._clients): self._loop.run_until_complete(c.close())
            except Exception: pass
            try: self._loop.close()
            except Exception: pass

def pack_std(msg_type: int, cmd: int, payload: bytes) -> bytes:
    return struct.pack("<HHI", msg_type, cmd, len(payload)) + payload

def pack_mini(msg_type: int, cmd: int = 0x0000) -> bytes:
    return struct.pack("<HHI", msg_type, cmd, 0)

def unpack_header8(data8: bytes):
    if len(data8) != 8: raise ValueError("header must be 8 bytes")
    return struct.unpack("<HHI", data8)

def try_extract_json(data: bytes):
    try: s = data.decode("utf-8", errors="ignore")
    except Exception: return None
    start = s.find("{")
    end = s.rfind("}")
    if start != -1 and end != -1 and end > start:
        snippet = s[start:end + 1]
        try: return json.loads(snippet)
        except Exception: return snippet
    return None

def rand_zip_name():
    letters = "abcdefghijklmnopqrstuvwxyz0123456789"
    mid = "".join(random.choice(letters) for _ in range(32))
    return f"iTGr{mid}.zip"

def hexdump(b: bytes, maxlen=256):
    if b is None: return ""
    return b[:maxlen].hex()

# --- NUOVA CLASSE WIZARD PER LA PROGRAMMAZIONE INTERATTIVA ---
class ProgrammingWizard(tk.Toplevel):
    """Finestra modale per guidare l'utente nella programmazione (EA->Wait->F8...)."""
    def __init__(self, parent, direction, app_ref):
        super().__init__(parent)
        self.title(f"Programmazione: {direction}")
        self.geometry("480x550")
        self.direction = direction
        self.app = app_ref
        
        # Registra questa finestra come wizard attivo nell'App
        self.app.active_wizard = self 
        
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
        self.step_labels = {}
        # Sequenza logica
        self.steps_order = ["INIT", "READ", "LOCK", "LISTEN", "MOTION", "STOP", "UNLOCK"]
        
        lbl_info = ttk.Label(self, text=f"Configurazione Direzione: {direction}", font=("Arial", 12, "bold"))
        lbl_info.pack(pady=10)
        
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill="both", expand=True)
        
        self._add_step(frame, "INIT", "1. Inizializzazione (EA)")
        self._add_step(frame, "READ", "2. Lettura Angoli (EB)")
        self._add_step(frame, "LOCK", "3. Blocco Totale Moduli (F8)")
        self._add_step(frame, "LISTEN", "4. Avvio Registrazione (F2)")
        self._add_step(frame, "MOTION", "5. IN ATTESA MOVIMENTO (F3)...")
        self._add_step(frame, "STOP", "6. Stop Registrazione (F2)")
        self._add_step(frame, "UNLOCK", "7. Sblocco Totale (F8)")
        
        self.btn_finish = ttk.Button(self, text="Concludi e Salva", command=self.on_finish, state="disabled")
        self.btn_finish.pack(pady=10, fill="x", padx=20)
        
        # Avvia la sequenza automatica
        self.after(500, self.run_sequence)

    def _add_step(self, parent, key, text):
        f = ttk.Frame(parent)
        f.pack(fill="x", pady=2)
        lbl_icon = ttk.Label(f, text="⏳", width=3)
        lbl_icon.pack(side="left")
        lbl_text = ttk.Label(f, text=text)
        lbl_text.pack(side="left")
        self.step_labels[key] = (lbl_icon, lbl_text)

    def mark_step(self, key, status="OK"):
        # --- FIX CRASH: Se la finestra non esiste più, esci senza errori ---
        if not self.winfo_exists(): return
        
        try:
            icon, txt = self.step_labels[key]
            if status == "OK":
                icon.config(text="✅", foreground="green")
                txt.config(foreground="green")
            elif status == "WAIT":
                icon.config(text="👀", foreground="orange")
                txt.config(foreground="orange", font=("Arial", 10, "bold"))
        except Exception:
            pass # Ignora errori se il widget specifico è stato distrutto

    def run_sequence(self):
        # --- FIX CRASH: Controllo iniziale ---
        if not self.winfo_exists(): return

        mods = sorted(self.app.get_all_module_ids())
        if not mods:
            messagebox.showerror("Errore", "Nessun modulo rilevato! Fai Connect prima.")
            self.on_cancel() 
            return
            
        ea_payload = bytearray(mods) 
        self.app._tx(pack_std(0x03EA, 0x0119, ea_payload), "EA Init")
        self.mark_step("INIT")
        self.update()
        time.sleep(0.2)
        if not self.winfo_exists(): return # Controllo dopo sleep
        
        self.app._tx(pack_std(0x03EB, 0x0000, bytes.fromhex("01fc0b02a60f057f0706b60b")), "EB Request")
        self.mark_step("READ")
        self.update()
        time.sleep(0.2)
        if not self.winfo_exists(): return
        
        self.app._on_lock_all_pressed(1) 
        self.mark_step("LOCK")
        self.update()
        time.sleep(0.2)
        if not self.winfo_exists(): return
        
        self.app._tx(pack_std(0x03F2, 0x006F, b"\x01"), "F2 Start Listen")
        self.mark_step("LISTEN")
        self.mark_step("MOTION", "WAIT")
        self.update()
        
        self.app._log("[WIZARD] In attesa che l'utente muova il robot (attendo 03F3)...\n")

    def on_f3_received(self, data):
        if not self.winfo_exists(): return
        icon_text = self.step_labels["MOTION"][0].cget("text")
        if icon_text != "✅":
            self.mark_step("MOTION", "OK")
            self.btn_finish.config(state="normal")

            self.app._log("[WIZARD] Movimento rilevato! Dettagli:\n")
            wheel_sample = {}

            for mid, val in data:
                self.app._log(f"   -> Modulo {mid}: spostamento {val}\n")

                # Salva snapshot ruote (soglia bassa: i tick 03F3 possono essere 10-20)
                if mid in self.app.robot_wheels and abs(int(val)) >= 5:
                    wheel_sample[int(mid)] = int(val)

                # --- AUTO-RILEVAMENTO POLARITÀ (Solo su UP) ---
                if self.direction == "UP" and mid in self.app.robot_wheels and abs(int(val)) >= 5:
                    sign = 1 if int(val) >= 0 else -1
                    self.app.wheel_polarity[int(mid)] = sign
                    self.app._log(f"   [AUTO-CALIB] Ruota {mid} -> Polarità impostata a {sign}\n")

            # Salva la snapshot 03F3 per la direzione (UP/LEFT/RIGHT) e prova auto-config SX/DX
            if wheel_sample:
                try:
                    self.app._save_wheel_sample_for_direction(self.direction, wheel_sample)
                except Exception as e:
                    self.app._log(f"[AUTO] Errore salvataggio 03F3: {e}\n")

            self.app._log("Premi Concludi per salvare.\n")

    def on_finish(self):
        if not self.winfo_exists(): return
        self.app._tx(pack_std(0x03F2, 0x0070, b"\x00"), "F2 Stop Listen")
        self.mark_step("STOP")
        self.update()
        time.sleep(0.2)
        
        self.app._on_lock_all_pressed(0)
        self.mark_step("UNLOCK")
        self.update()
        time.sleep(0.5)
        
        self.app.save_snapshot_for_direction(self.direction)
        try: self.app._auto_configure_wheels_from_samples()
        except Exception: pass
        
        self.app.active_wizard = None
        self.destroy()

    def on_cancel(self):
        self.app._on_lock_all_pressed(0)
        self.app.active_wizard = None
        self.destroy()



# --- NUOVA UI CONFIGURAZIONE RUOTE ---
class WheelConfigWindow(tk.Toplevel):
    """UI per dividere le ruote in DX e SX e INVERTIRE la polarità."""
    def __init__(self, parent, app_ref):
        super().__init__(parent)
        self.title("Configurazione Ruote")
        self.geometry("350x450")
        self.app = app_ref
        
        lbl = ttk.Label(self, text="Configura Lato e Polarità:", font=("Arial", 10, "bold"))
        lbl.pack(pady=10)
        
        self.side_vars = {} # mid -> stringvar ("L" or "R")
        self.inv_vars = {}  # mid -> intvar (1 = inverted)
        
        # Recupera tutte le ruote
        wheels = sorted(self.app.robot_wheels)
        if not wheels:
            ttk.Label(self, text="Nessuna ruota trovata.\nFai prima Connect!", foreground="red").pack(pady=20)
            return

        frame_list = ttk.Frame(self)
        frame_list.pack(fill="both", expand=True, padx=20)
        
        for mid in wheels:
            row = ttk.Frame(frame_list)
            row.pack(fill="x", pady=4)
            
            # Label ID
            ttk.Label(row, text=f"Ruota {mid}:", width=10).pack(side="left")
            
            # Stato Attuale Lato
            curr_side = "L" if mid in self.app.wheels_left else "R"
            v_side = tk.StringVar(value=curr_side)
            self.side_vars[mid] = v_side
            
            # Radio Buttons L/R
            ttk.Radiobutton(row, text="SX", variable=v_side, value="L").pack(side="left", padx=5)
            ttk.Radiobutton(row, text="DX", variable=v_side, value="R").pack(side="left", padx=5)
            
            # Checkbox Inverti
            # Se la polarità salvata è -1, la checkbox deve essere attiva
            curr_pol = self.app.wheel_polarity.get(mid, 1)
            is_inv = 1 if curr_pol == -1 else 0
            v_inv = tk.IntVar(value=is_inv)
            self.inv_vars[mid] = v_inv
            
            ttk.Checkbutton(row, text="Inverti", variable=v_inv).pack(side="right", padx=10)

        ttk.Button(self, text="Salva Configurazione", command=self.save).pack(pady=15)

    def save(self):
        self.app.wheels_left = []
        self.app.wheels_right = []
        self.app.wheel_polarity = {}
        
        for mid, v_side in self.side_vars.items():
            # Salva Lato
            if v_side.get() == "L":
                self.app.wheels_left.append(mid)
            else:
                self.app.wheels_right.append(mid)
            
            # Salva Polarità
            # Se checkbox attiva (1) -> polarità -1. Altrimenti 1.
            inv = self.inv_vars[mid].get()
            self.app.wheel_polarity[mid] = -1 if inv else 1
        
        self.app._log(f"[WHEELS] Saved. SX:{self.app.wheels_left} DX:{self.app.wheels_right}\n")
        self.app._log(f"[WHEELS] Polarity: {self.app.wheel_polarity}\n")
        self.app.wheels_manual_config = True
        self.destroy()

# ----------------- CLASSE ANIMAZIONE (BATCH UPLOAD & SMART PLAY) -----------------

# ----------------- CLASSE ANIMAZIONE (LOGICA EPSILON DAL JS) -----------------


class SteeringEditorWindow(tk.Toplevel):
    """
    Editor rapido per creare un'azione 'volante' (actType=2) dentro Animation Studio.
    Permette di programmare 3 direzioni: SU (UP), DX (RIGHT), SX (LEFT) usando lo stesso Wizard.
    """
    def __init__(self, parent, app_ref, default_name="volante1"):
        super().__init__(parent)
        self.app = app_ref
        self.result_action = None

        self.title("Nuovo volante")
        self.geometry("420x260")
        self.resizable(False, False)

        self._poses = {}    # dir -> {joint: angle}
        self._samples = {}  # dir -> {wheel: signed_val}

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Crea / programma un nuovo volante", font=("Arial", 11, "bold")).pack(anchor="w", pady=(0, 8))

        name_row = ttk.Frame(frm)
        name_row.pack(fill="x", pady=(0, 8))
        ttk.Label(name_row, text="Nome:").pack(side="left")
        self.var_name = tk.StringVar(value=str(default_name))
        ttk.Entry(name_row, textvariable=self.var_name).pack(side="left", fill="x", expand=True, padx=(8, 0))

        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(6, 10))

        ttk.Button(btns, text="⬆️ SU", command=lambda: self._program("UP")).pack(side="left", fill="x", expand=True, padx=2)
        ttk.Button(btns, text="➡️ DX", command=lambda: self._program("RIGHT")).pack(side="left", fill="x", expand=True, padx=2)
        ttk.Button(btns, text="⬅️ SX", command=lambda: self._program("LEFT")).pack(side="left", fill="x", expand=True, padx=2)

        self.lbl_status = ttk.Label(frm, text="Programma SU, DX e SX. Poi premi Salva.", foreground="gray")
        self.lbl_status.pack(anchor="w", pady=(0, 10))

        bottom = ttk.Frame(frm)
        bottom.pack(fill="x", pady=(4, 0))
        ttk.Button(bottom, text="💾 Salva", command=self._on_save).pack(side="right", padx=4)
        ttk.Button(bottom, text="Annulla", command=self._on_cancel).pack(side="right", padx=4)

        self._refresh_status()

    def _refresh_status(self):
        ok = []
        for d in ("UP", "RIGHT", "LEFT"):
            ok.append(f"{d}:{'OK' if (self._poses.get(d) and self._samples.get(d)) else '---'}")
        self.lbl_status.config(text="  ".join(ok))

    def _program(self, direction):
        # Lancia il wizard e aspetta che finisca (chiusura finestra)
        try:
            wiz = ProgrammingWizard(self, direction, self.app)
            self.wait_window(wiz)
        except Exception as e:
            messagebox.showerror("Wizard", str(e))
            return

        pose = (self.app.poses.get(direction) or None)
        sample = (getattr(self.app, "_wizard_wheel_samples", {}) or {}).get(direction)

        if not pose or not sample:
            messagebox.showwarning("Volante", f"Programmazione '{direction}' non completata.")
            return

        # Copia dati per evitare dipendenze su stato globale
        try:
            self._poses[direction] = {int(k): float(v) for k, v in dict(pose).items()}
        except Exception:
            self._poses[direction] = dict(pose)
        try:
            self._samples[direction] = {int(k): int(v) for k, v in dict(sample).items()}
        except Exception:
            self._samples[direction] = dict(sample)

        self._refresh_status()

    def _on_save(self):
        name = self.var_name.get().strip() or "volante"
        missing = [d for d in ("UP", "RIGHT", "LEFT") if not (self._poses.get(d) and self._samples.get(d))]
        if missing:
            messagebox.showwarning("Volante", "Mancano queste direzioni: " + ", ".join(missing))
            return

        try:
            act = self.app.build_drive_action_json_from_data(
                poses=self._poses,
                samples=self._samples,
                act_name=name,
                act_index=0
            )
            self.result_action = act
            self.destroy()
        except Exception as e:
            messagebox.showerror("Volante", str(e))

    def _on_cancel(self):
        self.result_action = None
        self.destroy()


class AnimationStudioWindow(tk.Toplevel):
    """
    Finestra per creare sequenze multiple (ACTIONS), editarle e gestire il robot.
    
    UPDATE LOGIC (Porting from JS):
    - Implementata logica "Epsilon" (0.01s) per stabilità Keyframe.
    - Gestione intelligente dei moduli: mantiene lo stato degli angoli se mancanti nello step.
    - Struttura Payload FE allineata 1:1 con l'App JS funzionante.
    """
    def __init__(self, parent, app_ref):
        super().__init__(parent)
        self.app = app_ref
        self.title("ClicBot Animation Studio - Multi Action Editor")
        self.geometry("1150x750")
        
        self.actions = []
        self.current_action_index = -1 
        self.clipboard_step = None     
        
        # --- LAYOUT ---
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=5, pady=5)
        
        # COLONNA SX
        frame_left = ttk.Frame(paned, width=350, padding=5)
        paned.add(frame_left, weight=1)
        
        lbl_list = ttk.Label(frame_left, text="Lista Movimenti (Actions)", font=("Arial", 10, "bold"))
        lbl_list.pack(pady=(0, 5))
        
        frm_list_btns = ttk.Frame(frame_left)
        frm_list_btns.pack(fill="x", pady=2)
        ttk.Button(frm_list_btns, text="➕ Aggiungi", command=self.add_new_action).pack(side="left", fill="x", expand=True, padx=2)
        ttk.Button(frm_list_btns, text="🗑 Elimina", command=self.delete_current_action).pack(side="left", fill="x", expand=True, padx=2)
        ttk.Button(frm_list_btns, text="🛞 Nuovo volante", command=self.add_new_steering_action).pack(side="left", fill="x", expand=True, padx=2)
        self.btn_show_drive_json = ttk.Button(frm_list_btns, text="🧾 Mostra JSON direzioni", command=self.show_selected_drive_json, state="disabled")
        self.btn_show_drive_json.pack(side="left", fill="x", expand=True, padx=2)
        
        self.lst_actions = tk.Listbox(frame_left, height=12, selectmode="browse", exportselection=False, font=("Consolas", 10))
        self.lst_actions.pack(fill="x", pady=2)
        self.lst_actions.bind("<<ListboxSelect>>", self.on_action_select)
        
        self.btn_play = ttk.Button(frame_left, text="▶️ RIPRODUCI SELEZIONATO", command=self.play_logic)
        self.btn_play.pack(fill="x", pady=(5, 10))

        ttk.Separator(frame_left, orient="horizontal").pack(fill="x", pady=5)
        
        lbl_det = ttk.Label(frame_left, text="Dettagli & Slot", font=("Arial", 10, "bold"))
        lbl_det.pack(pady=(5, 5))
        
        frm_meta = ttk.Frame(frame_left)
        frm_meta.pack(fill="x", pady=2)
        ttk.Label(frm_meta, text="Nome:").grid(row=0, column=0, sticky="w")
        self.ent_act_name = ttk.Entry(frm_meta, width=20)
        self.ent_act_name.grid(row=0, column=1, padx=5, sticky="ew")
        self.ent_act_name.bind("<FocusOut>", self.on_name_change) 
        self.ent_act_name.bind("<Return>", self.on_name_change)
        
        ttk.Label(frm_meta, text="Slot ID:").grid(row=1, column=0, sticky="w")
        self.var_slot = tk.IntVar(value=0)
        self.spn_slot = ttk.Spinbox(frm_meta, from_=0, to=255, textvariable=self.var_slot, width=5, command=self.on_slot_change)
        self.spn_slot.grid(row=1, column=1, padx=5, sticky="w")
        self.spn_slot.bind("<FocusOut>", self.on_slot_change)
        self.spn_slot.bind("<Return>", self.on_slot_change)

        ttk.Separator(frame_left, orient="horizontal").pack(fill="x", pady=15)

        lbl_cap = ttk.Label(frame_left, text="Aggiungi Step", font=("Arial", 10, "bold"))
        lbl_cap.pack(pady=(0, 5))
        frm_params = ttk.Frame(frame_left)
        frm_params.pack(fill="x")
        ttk.Label(frm_params, text="Exec (s):").pack(side="left")
        self.var_exec = tk.DoubleVar(value=0.05)
        ttk.Entry(frm_params, textvariable=self.var_exec, width=6).pack(side="left", padx=5)
        ttk.Label(frm_params, text="Delay (s):").pack(side="left")
        self.var_delay = tk.DoubleVar(value=0.0)
        ttk.Entry(frm_params, textvariable=self.var_delay, width=6).pack(side="left", padx=5)
        
        ttk.Button(frame_left, text="📸 CATTURA POSA", command=self.safe_add_snapshot).pack(fill="x", pady=5)
        
        ttk.Separator(frame_left, orient="horizontal").pack(fill="x", pady=15)
        
        frm_io = ttk.Frame(frame_left)
        frm_io.pack(fill="x", pady=5)
        ttk.Button(frm_io, text="📂 IMPORTA", command=self.import_json).pack(side="left", fill="x", expand=True, padx=2)
        ttk.Button(frm_io, text="💾 SALVA", command=self.export_json).pack(side="left", fill="x", expand=True, padx=2)
        
        self.lbl_status = ttk.Label(frame_left, text="Inizializzazione...", foreground="gray", wraplength=250)
        self.lbl_status.pack(side="bottom", pady=10)

        # COLONNA DX
        frame_right = ttk.LabelFrame(paned, text="Timeline", padding=5)
        paned.add(frame_right, weight=4)
        
        cols = ("Idx", "ExecTime", "MinTime", "Delay", "Joints")
        self.tree = ttk.Treeview(frame_right, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("Idx", text="#")
        self.tree.column("Idx", width=40, anchor="center")
        self.tree.heading("ExecTime", text="Exec(s) ✎") 
        self.tree.column("ExecTime", width=70, anchor="center")
        self.tree.heading("MinTime", text="Min(s)")
        self.tree.column("MinTime", width=70, anchor="center")
        self.tree.heading("Delay", text="Delay(s) ✎")
        self.tree.column("Delay", width=70, anchor="center")
        self.tree.heading("Joints", text="Dettagli Angoli")
        self.tree.column("Joints", width=400)
        
        sb = ttk.Scrollbar(frame_right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=sb.set)
        self.tree_sb = sb
        
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # --- Drive table (Volante / actType=2) ---
        self.drive_frame = ttk.Frame(frame_right)
        dcols = ("Dir", "Joints", "Wheels")
        self.drive_tree = ttk.Treeview(self.drive_frame, columns=dcols, show="headings", selectmode="browse")
        self.drive_tree.heading("Dir", text="Direzione")
        self.drive_tree.column("Dir", width=80, anchor="center")
        self.drive_tree.heading("Joints", text="Giunti")
        self.drive_tree.column("Joints", width=70, anchor="center")
        self.drive_tree.heading("Wheels", text="Ruote (segno+vel)")
        self.drive_tree.column("Wheels", width=520, anchor="w")
        self.drive_sb = ttk.Scrollbar(self.drive_frame, orient="vertical", command=self.drive_tree.yview)
        self.drive_tree.configure(yscroll=self.drive_sb.set)
        # NON pack qui: viene mostrato solo quando selezioni un volante
        self.drive_tree.bind("<Double-1>", self.on_drive_double_click)

        
        self.tree.bind("<Double-1>", self.on_tree_double_click)
        self.tree.bind("<Button-3>", self.show_context_menu) 
        
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copia Riga", command=self.copy_row)
        self.context_menu.add_command(label="Incolla Riga", command=self.paste_row)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Elimina Riga", command=self.remove_step)
        self.context_menu.add_command(label="Ricalcola MinTime", command=self.recalc_min_times)

        self.add_new_action(default=True)
        self.after(500, self._send_initialization_sequence)

    # --- AZIONI & LISTA ---

    def add_new_steering_action(self):
        # Genera nome automatico volanteN
        existing = set()
        for a in self.actions:
            try:
                if int(a.get("actType", 0) or 0) == 2:
                    existing.add(str(a.get("actName", "")).strip())
            except Exception:
                pass
        n = 1
        while f"volante{n}" in existing:
            n += 1
        default_name = f"volante{n}"

        win = SteeringEditorWindow(self, self.app, default_name=default_name)
        self.wait_window(win)
        act = getattr(win, "result_action", None)
        if not act:
            return

        # Inserisci in lista
        self.actions.append(act)
        self._refresh_action_list_ui()
        self.lst_actions.selection_clear(0, "end")
        self.lst_actions.selection_set(len(self.actions) - 1)
        self.on_action_select(None)


    def add_new_action(self, default=False):
        if default and not self.actions: name, idx = "move_1", 0
        else:
            existing = sorted([a["actIndex"] for a in self.actions])
            idx = 0
            for i in existing:
                if idx == i: idx += 1
                else: break
            cnt = 1
            while True:
                name = f"move_{cnt}"
                if not any(a["actName"] == name for a in self.actions): break
                cnt += 1
        self.actions.append({"actIndex": idx, "actName": name, "actType": 0, "isSelect": False, "model_id": 0, "STEP": []})
        self._refresh_action_list_ui()
        self.lst_actions.selection_clear(0, "end")
        self.lst_actions.selection_set(self.lst_actions.size()-1)
        self.on_action_select(None)

    def delete_current_action(self):
        if len(self.actions) <= 1 or self.current_action_index < 0: return
        if messagebox.askyesno("Conferma", "Eliminare?"):
            del self.actions[self.current_action_index]
            self.current_action_index = -1
            self._refresh_action_list_ui()
            self.lst_actions.selection_set(0)
            self.on_action_select(None)

    def _refresh_action_list_ui(self):
        self.lst_actions.delete(0, "end")
        for a in self.actions:
            try:
                icon = "🛞 " if int(a.get("actType", 0) or 0) == 2 else ""
            except Exception:
                icon = ""
            self.lst_actions.insert("end", f"{icon}[{a.get('actIndex', 0)}] {a.get('actName', '')}")

    def on_action_select(self, event):
        sel = self.lst_actions.curselection()
        if not sel:
            return
        idx = sel[0]
        self.current_action_index = idx
        a = self.actions[idx]
        self.ent_act_name.delete(0, "end")
        self.ent_act_name.insert(0, a["actName"])
        self.var_slot.set(a["actIndex"])
        self._refresh_tree()

        # Se è un volante (actType=2), rendilo attivo per la schermata guida
        try:
            if int(a.get("actType", 0) or 0) == 2:
                self.app.apply_volante_action_to_drive(a)
                if hasattr(self, "btn_show_drive_json"):
                    self.btn_show_drive_json.config(state="normal")
            else:
                if hasattr(self, "btn_show_drive_json"):
                    self.btn_show_drive_json.config(state="disabled")
        except Exception:
            if hasattr(self, "btn_show_drive_json"):
                self.btn_show_drive_json.config(state="disabled")


    def on_name_change(self, event=None):
        if self.current_action_index >= 0:
            self.actions[self.current_action_index]["actName"] = self.ent_act_name.get().strip()
            self._refresh_action_list_ui()
            self.lst_actions.selection_set(self.current_action_index)

    def on_slot_change(self, event=None):
        if self.current_action_index >= 0:
            try:
                self.actions[self.current_action_index]["actIndex"] = self.var_slot.get()
                self._refresh_action_list_ui()
                self.lst_actions.selection_set(self.current_action_index)
            except: pass

    # --- EDITING ---
    def on_tree_double_click(self, event):
        if self.current_action_index < 0: return
        steps = self.actions[self.current_action_index]["STEP"]
        col, item = self.tree.identify_column(event.x), self.tree.identify_row(event.y)
        if not item: return
        idx = int(self.tree.item(item, "values")[0])
        keys = {"#2": "executeTime", "#4": "delayTime"}
        if col in keys:
            key = keys[col]
            bbox = self.tree.bbox(item, col)
            entry = ttk.Entry(self.tree, width=10)
            entry.place(x=bbox[0], y=bbox[1], w=bbox[2], h=bbox[3])
            entry.insert(0, steps[idx].get(key, 0.0))
            entry.select_range(0, "end"); entry.focus()
            def save(e):
                try: steps[idx][key] = float(entry.get()); entry.destroy(); self._refresh_tree()
                except: entry.destroy()
            entry.bind("<Return>", save); entry.bind("<FocusOut>", save)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item: self.tree.selection_set(item); self.context_menu.post(event.x_root, event.y_root)

    def on_drive_double_click(self, event):
        if self.current_action_index < 0:
            return
        act = self.actions[self.current_action_index]
        try:
            if int(act.get("actType", 0) or 0) != 2:
                return
        except Exception:
            return

        item = self.drive_tree.identify_row(event.y)
        if not item:
            return
        dkey = str(item).upper().strip()
        self.edit_drive_direction(dkey)

    def edit_drive_direction(self, dkey):
        if self.current_action_index < 0:
            return
        act = self.actions[self.current_action_index]
        try:
            if int(act.get("actType", 0) or 0) != 2:
                return
        except Exception:
            return

        dkey = str(dkey).upper().strip()
        if dkey not in ("UP", "LEFT", "RIGHT"):
            return

        try:
            wiz = ProgrammingWizard(self, dkey, self.app)
            self.wait_window(wiz)
        except Exception as e:
            messagebox.showerror("Wizard", str(e))
            return

        pose = self.app.poses.get(dkey)
        sample = (getattr(self.app, "_wizard_wheel_samples", {}) or {}).get(dkey)

        if not pose or not sample:
            messagebox.showwarning("Volante", f"Programmazione '{dkey}' non completata.")
            return

        try:
            posture = self.app._build_drive_posture(pose, sample)
            self._apply_drive_posture_to_action(act, dkey, posture)
            self._refresh_tree()
        except Exception as e:
            messagebox.showerror("Volante", str(e))

    def _apply_drive_posture_to_action(self, act, direction, posture):
        if "STEP" not in act or not isinstance(act["STEP"], list):
            act["STEP"] = []

        step_map = {}
        for s in act["STEP"]:
            try:
                step_map[int(s.get("stepIndex", -1))] = s
            except Exception:
                pass

        def set_step(step_idx):
            s = step_map.get(step_idx)
            if not s:
                s = {
                    "POSTURE": [],
                    "delayTime": 0.0,
                    "executeTime": 0.0,
                    "groupNumber": 0,
                    "isGroupNode": 0,
                    "minExecuteTime": 0.0,
                    "segmentIndex": 0,
                    "startTime": 0.0,
                    "steeringIndex": -1,
                    "stepIndex": int(step_idx),
                }
                act["STEP"].append(s)
                step_map[step_idx] = s
            s["POSTURE"] = posture

        if direction == "UP":
            set_step(1)
            set_step(2)
        elif direction == "RIGHT":
            set_step(3)
        elif direction == "LEFT":
            set_step(4)

        act["STEP"].sort(key=lambda x: int(x.get("stepIndex", 0)))


    def copy_row(self):
        sel = self.tree.selection()
        if sel: 
            import copy
            idx = int(self.tree.item(sel[0], "values")[0])
            self.clipboard_step = copy.deepcopy(self.actions[self.current_action_index]["STEP"][idx])

    def paste_row(self):
        if self.clipboard_step and self.current_action_index >= 0:
            import copy
            new = copy.deepcopy(self.clipboard_step)
            steps = self.actions[self.current_action_index]["STEP"]
            new["stepIndex"] = len(steps)
            steps.append(new)
            self._refresh_tree()

    def remove_step(self):
        sel = self.tree.selection()
        if sel:
            steps = self.actions[self.current_action_index]["STEP"]
            del steps[int(self.tree.item(sel[0], "values")[0])]
            for i, s in enumerate(steps): s["stepIndex"] = i
            self._refresh_tree()

    def recalc_min_times(self):
        if self.current_action_index < 0: return
        self._recalc_all_min_times_on_import([self.actions[self.current_action_index]])
        self._refresh_tree()

    # --- IMPORT / EXPORT ---
    def import_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path: return
        try:
            with open(path, "r") as f: data = json.load(f)
            loaded = data.get("ACTIONS", [])
            if not loaded: raise ValueError("JSON invalido o vuoto")
            self._recalc_all_min_times_on_import(loaded)
            self.actions = loaded
            self.current_action_index = 0
            self._refresh_action_list_ui()
            self.lst_actions.selection_set(0)
            self.on_action_select(None)
            self.lbl_status.config(text=f"Caricate {len(loaded)} azioni.")
            self.after(500, self.upload_all_to_robot) 
        except Exception as e: messagebox.showerror("Errore", str(e))

    def _recalc_all_min_times_on_import(self, actions_list):
        for action in actions_list:
            steps = action.get("STEP", [])
            steps.sort(key=lambda s: int(s.get("stepIndex", 0)))
            for i in range(len(steps)):
                if i == 0: steps[i]["minExecuteTime"] = 0.0; continue
                curr, prev = steps[i].get("POSTURE", []), steps[i-1].get("POSTURE", [])
                pmap = {p["moduleId"]: float(p["angle"]) for p in prev}
                max_d = 0.0
                for n in curr:
                    mid, ang = n["moduleId"], float(n["angle"])
                    diff = abs(ang - pmap.get(mid, ang))
                    if diff > 180: diff = 360 - diff
                    if diff > max_d: max_d = diff
                steps[i]["minExecuteTime"] = round(max_d / 200.0, 6)

    def export_json(self):
        if not self.actions:
            return
        path = filedialog.asksaveasfilename(
            initialfile="robot.json",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")]
        )
        if not path:
            return

        # Deep copy (evita riferimenti live)
        actions_out = json.loads(json.dumps(self.actions))

        # Rimuovi eventuali chiavi "interne" (se mai presenti)
        for a in actions_out:
            for k in list(a.keys()):
                if str(k).startswith("_"):
                    a.pop(k, None)

        # Se non c'è nessun volante (actType=2) ma l'utente ha programmato SU/SX/DX,
        # prova ad aggiungere automaticamente l'azione steering (compatibilità).
        if not any(int(a.get("actType", 0) or 0) == 2 for a in actions_out):
            try:
                drive = self.app.build_drive_action_json(act_name="steering")
                actions_out.append(drive)
            except Exception:
                pass

        # --- Merge intelligente: actIndex univoci, volante principale in slot 0 ---
        steering = [a for a in actions_out if int(a.get("actType", 0) or 0) == 2]
        others = [a for a in actions_out if int(a.get("actType", 0) or 0) != 2]

        used = set()

        if steering:
            # volante principale -> 0
            steering[0]["actIndex"] = 0
            used.add(0)
            nxt = 1
            for a in steering[1:]:
                while nxt in used:
                    nxt += 1
                a["actIndex"] = nxt
                used.add(nxt)
                nxt += 1

        nxt = 0
        for a in others:
            try:
                idx = int(a.get("actIndex", 0))
            except Exception:
                idx = 0
            if idx in used:
                while nxt in used:
                    nxt += 1
                a["actIndex"] = nxt
                used.add(nxt)
                nxt += 1
            else:
                used.add(idx)

        ordered = steering + others

        with open(path, "w") as f:
            json.dump({"ACTIONS": ordered}, f, indent=None, separators=(',', ':'))

        messagebox.showinfo("Info", "Salvato.")


    def upload_all_to_robot(self):
        if not self.actions or not self.app.sock: return
        try:
            for act in self.actions:
                if int(act.get("actType", 0) or 0) != 0:
                    continue
                steps, slot = act.get("STEP", []), int(act.get("actIndex", 0))
                if len(steps) < 2:
                    continue
                pl = self._build_fe_payload(steps, slot)
                self.app._tx(pack_std(0x03FE, self._next_cmd(), pl), f"Upload {slot}")
                time.sleep(0.15)
                self.app._tx(pack_std(0x03FF, self._next_cmd(), struct.pack("<BB", 1, slot)), f"Init {slot}")
                time.sleep(0.1)
            self.lbl_status.config(text="Upload completato.")
        except Exception as e: messagebox.showerror("Err", str(e))

    # --- PLAYBACK LOGIC ---
    def play_logic(self):
        if self.current_action_index < 0: return
        act = self.actions[self.current_action_index]
        steps = act["STEP"]
        slot = int(act["actIndex"])
        if not steps: return
        
        self.lbl_status.config(text=f"Play '{act['actName']}' Slot {slot}...")
        self.update()
        
        if len(steps) == 1: self._play_single_step(steps[0])
        else: self._play_full_animation(steps, slot)

    def _play_single_step(self, step):
        post = step.get("POSTURE", [])
        if not post: return
        pl = bytearray()
        
        # --- MODIFICA: FORZA 0.05s PER I COMANDI SINGOLI ---
        # Ignoriamo il valore della casella di testo (self.var_exec) per il test singolo.
        # Usiamo 0.05s (50ms) per garantire che il movimento avvenga subito.
        ex = 0.05 
        t_ms = int(ex * 1000) # 50 ms
        
        mids = []
        for p in post:
            mid = int(p["moduleId"])
            mids.append(mid)
            # Calcolo angolo Raw
            raw = int((float(p["angle"]) % 360.0) / 360.0 * 4096.0) & 0xFFFF
            # Costruzione payload per questo motore
            pl.extend(struct.pack("<BBHH", mid, 0x02, t_ms, raw))
        
        # 1. Sblocca (Reset stato)
        self._set_motor_lock(mids, 0)
        time.sleep(0.02)
        
        # 2. Invia Comando Movimento (0x03F0) con tempo forzato a 50ms
        self.app._tx(pack_std(0x03F0, self._next_cmd(), pl), "Single F0 (Fast 0.05s)")
        
        # 3. Attesa (Tempo movimento + piccolo buffer)
        # Se ex=0.05, dormiamo 0.15s totali. Sufficiente per lo scatto.
        time.sleep(ex + 2)
        
        # 4. Sgancia i motori (Rilascia)
        self._set_motor_lock(mids, 0)
        self.lbl_status.config(text="Posa singola eseguita (Fast Mode).")

    def _play_full_animation(self, steps, slot):
        try: payload = self._build_fe_payload(steps, slot)
        except Exception as e: messagebox.showerror("Err", str(e)); return

        tot_time = sum([float(s.get("executeTime",0)) + float(s.get("delayTime",0)) for s in steps])
        
        self.app._tx(pack_std(0x03FE, self._next_cmd(), payload), f"Upload {slot}")
        time.sleep(0.1)
        self.app._tx(pack_std(0x03FF, self._next_cmd(), struct.pack("<BB", 1, slot)), f"Start {slot}")
        time.sleep(0.05)
        self.app._tx(pack_std(0x03F6, self._next_cmd(), struct.pack("<B", slot)), f"Mode {slot}")
        
        self.lbl_status.config(text=f"Esecuzione (Wait {tot_time:.1f}s)...")
        self.update()
        time.sleep(tot_time + 1)
        
        mids = set()
        for s in steps:
            for p in s.get("POSTURE", []): mids.add(int(p["moduleId"]))
        self._set_motor_lock(list(mids), 0)
        self.lbl_status.config(text="Fine.")

    # -----------------------------------------------------------
    # IMPLEMENTAZIONE LOGICA EPSILON (PORTING DAL JS)
    # -----------------------------------------------------------
    def _build_fe_payload(self, steps, slot_idx):
        EPS = 0.01
        
        # Ordina steps
        steps = sorted(steps, key=lambda s: int(s.get("stepIndex", 0)))
        if not steps: return bytearray()

        # 1. Trova tutti i moduleID coinvolti (Union set)
        all_mids = set()
        for s in steps:
            for p in s.get("POSTURE", []): all_mids.add(int(p["moduleId"]))
        mids = sorted(list(all_mids))
        if not mids: return bytearray()

        # 2. Inizializza angoli correnti (stato iniziale a step 0)
        curr_angles = {mid: None for mid in mids}
        
        # Popola con step 0
        for p in steps[0].get("POSTURE", []):
            mid = int(p["moduleId"])
            if mid in curr_angles: curr_angles[mid] = float(p["angle"])
            
        # Se mancano moduli in step 0, cerca nei successivi (Fallback)
        for mid in mids:
            if curr_angles[mid] is None:
                for s in steps[1:]:
                    found = next((p for p in s.get("POSTURE", []) if int(p["moduleId"]) == mid), None)
                    if found: curr_angles[mid] = float(found["angle"]); break
                # Se ancora None, metti 0.0
                if curr_angles[mid] is None: curr_angles[mid] = 0.0

        # 3. Struttura dati temporale: mod_times[mid] = list of (time, angle)
        mod_times = {mid: [] for mid in mids}

        # Aggiungi Start Points (0 e EPS)
        for mid in mids:
            ang = curr_angles[mid]
            mod_times[mid].append((0.0, ang))
            mod_times[mid].append((EPS, ang))

        # 4. Processa eventi (Execution End e Delay End)
        t = 0.0
        events = [] # List of {t: float, angles: dict}

        # Itera da step 1 in poi (step 0 è lo stato iniziale)
        for i in range(1, len(steps)):
            s = steps[i]
            exec_t = max(0.0, float(s.get("executeTime", 0.0)))
            t += exec_t
            
            # Aggiorna angoli per questo step
            for p in s.get("POSTURE", []):
                mid = int(p["moduleId"])
                if mid in curr_angles: curr_angles[mid] = float(p["angle"])
            
            # Registra evento Fine Esecuzione
            events.append({"t": t, "angles": curr_angles.copy()})
            
            # Gestione Delay
            delay_t = max(0.0, float(s.get("delayTime", 0.0)))
            if delay_t > 1e-9:
                t += delay_t
                # Registra evento Fine Delay (angoli invariati)
                events.append({"t": t, "angles": curr_angles.copy()})

        # 5. Genera Keyframe Epsilon per ogni evento
        for idx, ev in enumerate(events):
            is_last = (idx == len(events) - 1)
            t_ev = ev["t"]
            t_minus = max(0.0, t_ev - EPS)
            t_zero = max(t_minus, t_ev)
            t_plus = t_ev + EPS
            
            for mid in mids:
                ang = ev["angles"][mid]
                mod_times[mid].append((t_minus, ang))
                mod_times[mid].append((t_zero, ang))
                if not is_last:
                    mod_times[mid].append((t_plus, ang))

        # 6. Costruisci Payload Binario
        payload = bytearray()
        for mid in mids:
            points = mod_times[mid]
            # [ID:1][Slot:1][Len:4]
            payload.extend(struct.pack("<BB", mid, slot_idx))
            payload.extend(struct.pack("<I", len(points) * 8))
            
            # Points: [Time:4][Angle:4] -> CONFIRMED CORRECT ORDER from JS code
            # "dv.setFloat32(off, Number(pt.t), true)... dv.setFloat32(off, Number(pt.a), true)"
            for (pt_t, pt_a) in points:
                payload.extend(struct.pack("<ff", float(pt_t), float(pt_a)))
                
        return bytes(payload)

    # --- UTILS ---
    def _send_initialization_sequence(self):
        if not self.app.sock: return
        ids = sorted([k for k in self.app._structure_by_index.keys()]) if self.app._structure_by_index else [1, 2, 5]
        for mid in ids:
            self.app._tx(pack_std(0x03F8, self._next_cmd(), struct.pack("<BB", mid, 0)), f"Init F8 {mid}")
            time.sleep(0.01)
        self.app._tx(pack_std(0x03FC, self._next_cmd(), b"\x00\x00"), "Init FC")
        bulk = bytearray()
        for i in range(1, 8): bulk.extend(struct.pack("<BB", i, 0))
        self.app._tx(pack_std(0x03F8, self._next_cmd(), bulk), "Init F8 Bulk")
        self.lbl_status.config(text="Pronto.", foreground="green")

    def _set_motor_lock(self, mids, s):
        for m in sorted(list(set(mids))):
            self.app._tx(pack_std(0x03F8, self._next_cmd(), struct.pack("<BB", m, s)), f"Lock {m}={s}")
            time.sleep(0.01)

    def _next_cmd(self):
        c = int(getattr(self.app, "_cmd_counter_std", 0)) & 0xFFFF
        self.app._cmd_counter_std = (c + 1) & 0xFFFF
        return c

    def safe_add_snapshot(self):
        if self.current_action_index < 0: return
        post = self._get_current_postures()
        if not post: messagebox.showwarning("Info", "Nessun modulo."); return
        steps = self.actions[self.current_action_index]["STEP"]
        min_t = 0.0
        if steps:
            pmap = {p["moduleId"]: float(p["angle"]) for p in steps[-1]["POSTURE"]}
            max_d = 0.0
            for p in post:
                d = abs(p["angle"] - pmap.get(p["moduleId"], p["angle"]))
                if d > 180: d = 360 - d
                if d > max_d: max_d = d
            min_t = round(max_d / 200.0, 3)
        usr = float(self.var_exec.get())
        act_type = 0
        try:
            act_type = int(self.actions[self.current_action_index].get("actType", 0) or 0)
        except Exception:
            act_type = 0
        steering_idx = 0 if act_type == 2 else -1
        new = {
            "POSTURE": post, "delayTime": float(self.var_delay.get()), 
            "executeTime": max(usr, min_t), "minExecuteTime": min_t,
            "stepIndex": len(steps), "groupNumber": 0, "isGroupNode": 0, "segmentIndex": 0, "startTime": 0.0, "steeringIndex": steering_idx
        }
        steps.append(new)
        self._refresh_tree()

    def _get_current_postures(self):
        """Ritorna la POSTURE corrente (solo giunti type=1) nel formato robot.json."""
        r = []
        if not getattr(self.app, "_structure_by_index", None):
            return []
        for mid, node in self.app._structure_by_index.items():
            try:
                if node.get("type") != 1:
                    continue
                r.append({
                    "angle": float(node.get("angle", 0.0)),
                    "forward": False,
                    "inTangent": 0.0,
                    "inWeight": 0.0,
                    "moduleId": int(mid),
                    "moduleRotateForward": False,
                    "outTangent": 0.0,
                    "outWeight": 0.0,
                    "rotate": False,
                    "speed": 0,
                    "type": 1
                })
            except Exception:
                continue
        r.sort(key=lambda x: int(x.get("moduleId", 0)))
        return r


    def _show_timeline_table(self):
        # Mostra la tabella classica e nasconde quella del volante
        try:
            if hasattr(self, "drive_frame") and self.drive_frame.winfo_ismapped():
                self.drive_frame.pack_forget()
        except Exception:
            pass
        try:
            if not self.tree.winfo_ismapped():
                self.tree.pack(side="left", fill="both", expand=True)
                self.tree_sb.pack(side="right", fill="y")
        except Exception:
            pass

    def _show_drive_table(self):
        # Mostra la tabella volante e nasconde la tabella classica
        try:
            if self.tree.winfo_ismapped():
                self.tree.pack_forget()
                self.tree_sb.pack_forget()
        except Exception:
            pass
        try:
            if not self.drive_frame.winfo_ismapped():
                self.drive_frame.pack(side="left", fill="both", expand=True)
                self.drive_tree.pack(side="left", fill="both", expand=True)
                self.drive_sb.pack(side="right", fill="y")
        except Exception:
            pass

    def _refresh_drive_tree(self, act):
        for i in self.drive_tree.get_children():
            self.drive_tree.delete(i)

        steps = act.get("STEP", []) or []
        by_idx = {}
        for s in steps:
            try:
                by_idx[int(s.get("stepIndex", -1))] = s
            except Exception:
                pass

        def fmt_wheels(step):
            if not step:
                return "(non programmato)"
            wheels = [p for p in (step.get("POSTURE", []) or []) if int(p.get("type", 0) or 0) == 3]
            if not wheels:
                return "(nessuna ruota)"
            parts = []
            for p in wheels:
                mid = int(p.get("moduleId", 0) or 0)
                sp = int(p.get("speed", 0) or 0)
                sign = "+" if bool(p.get("forward", True)) else "-"
                parts.append(f"{mid:02d}:{sign}{sp:02d}")
            s = " ".join(parts)
            return (s[:120] + "...") if len(s) > 123 else s

        def count_joints(step):
            if not step:
                return 0
            return sum(1 for p in (step.get("POSTURE", []) or []) if int(p.get("type", 0) or 0) == 1)

        rows = [
            ("SU", "UP", 1),
            ("DX", "RIGHT", 3),
            ("SX", "LEFT", 4),
        ]
        for label, dkey, sidx in rows:
            step = by_idx.get(sidx)
            jn = count_joints(step)
            ws = fmt_wheels(step)
            self.drive_tree.insert("", "end", iid=dkey, values=(label, jn, ws))

    def _refresh_tree(self):
        if self.current_action_index < 0:
            return

        act = self.actions[self.current_action_index]
        act_type = 0
        try:
            act_type = int(act.get("actType", 0) or 0)
        except Exception:
            act_type = 0

        if act_type == 2:
            self._show_drive_table()
            self._refresh_drive_tree(act)
            return

        self._show_timeline_table()

        for i in self.tree.get_children():
            self.tree.delete(i)

        steps = act.get("STEP", []) or []
        for i, s in enumerate(steps):
            posture = s.get("POSTURE", []) or []
            j = " | ".join([f"ID{p.get('moduleId', 0)}:{int(p.get('angle', 0))}" for p in posture[:4]])
            if len(posture) > 4:
                j += "..."
            self.tree.insert(
                "", "end",
                values=(
                    i,
                    round(float(s.get("executeTime", 0.0) or 0.0), 3),
                    round(float(s.get("minExecuteTime", 0.0) or 0.0), 3),
                    round(float(s.get("delayTime", 0.0) or 0.0), 3),
                    j
                )
            )




    def show_selected_drive_json(self):
        """Mostra il JSON (formattato) della direzione/volante selezionata (actType=2)."""
        if self.current_action_index < 0:
            return
        act = self.actions[self.current_action_index]
        try:
            if int(act.get("actType", 0) or 0) != 2:
                messagebox.showinfo("JSON Direzioni", "Seleziona un'azione 'volante' (actType=2) nella lista.")
                return
        except Exception:
            messagebox.showinfo("JSON Direzioni", "Seleziona un'azione 'volante' (actType=2) nella lista.")
            return

        txt_json = json.dumps(act, indent=2, ensure_ascii=False)

        win = tk.Toplevel(self)
        win.title("JSON Direzioni (volante)")
        win.geometry("820x520")
        win.transient(self)

        frm = ttk.Frame(win, padding=10)
        frm.pack(fill="both", expand=True)

        top = ttk.Frame(frm)
        top.pack(fill="x")
        ttk.Label(top, text=f"Azione: {act.get('actName','volante')}  (actType=2)", font=("Arial", 11, "bold")).pack(side="left")
        ttk.Button(top, text="Copia", command=lambda: (win.clipboard_clear(), win.clipboard_append(txt_json))).pack(side="right")

        txtw = tk.Text(frm, wrap="none", font=("Consolas", 10))
        txtw.pack(fill="both", expand=True, pady=(8,0))

        ysb = ttk.Scrollbar(frm, orient="vertical", command=txtw.yview)
        ysb.place(relx=1.0, rely=0.16, relheight=0.84, anchor="ne")
        txtw.configure(yscrollcommand=ysb.set)

        txtw.insert("1.0", txt_json)
        txtw.config(state="disabled")


# ----------------- APP PRINCIPALE -----------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ClicBot Dev Tools 1.0")
        self.geometry("1050x760")
        self._app_icon_img = None
        self._apply_app_icon()
        self.lang_var = tk.StringVar(value="English")
        self._lang_code = "en"
        self._it_to_en = self._build_translations()
        self._en_to_it = {v: k for k, v in self._it_to_en.items()}
        self._install_messagebox_i18n()
        self._assembly_active = False
        self._activation_ok = False

        self.sock = None
        # --- NUOVO SOCKET UDP ---
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        self.running = False
        self.rx_thread = None
        self.keepalive_thread = None
        self.sock_lock = threading.Lock()
        self.keepalive_pause = threading.Event()
        self.keepalive_pause.clear()
        self.log_q = queue.Queue()

        self.ws_port_var = tk.IntVar(value=8787)
        self.ws_bridge = WsBridge(port=self.ws_port_var.get(), log=self._log)
        self.ws_enabled = False

        self._structure_json = None
        self._structure_by_index = {}
        self._last_structure_json_text = ""
        self._json_win = None
        self._json_text_widget = None
        self._modules_win = None
        self._modules_widgets = {}
        self._f8_cmd_counter = 0x0184
        
        # NUOVO: Stato Drive Mode
        self._drive_mode_active = False 
        self._cmd_counter_std = 0x0020 # Contatore per comandi STD generici
        
        # Reference al Wizard attivo (se c'è)
        self.active_wizard = None

        # --- VARIABILI DINAMICHE PER JOYSTICK (NO HARDCODING) ---
        self.last_joy_time = 0
        self.last_sent_joy_data = (0.0, 0.0) # NUOVO: per filtro delta
        self.robot_wheels = [] # Lista mIndex ruote (Type 3)
        self.robot_joints = [] # Lista mIndex sfere (Type 1)
        self.robot_distance = []

        # --- NUOVE VARIABILI PER UDP DRIVE E SPEED ---
        self.wheels_left = []
        self.wheels_right = []
        self.wheel_polarity = {}
        self._wizard_wheel_samples = {}  # direction -> {wheel_id: raw_val}
        self.wheels_manual_config = False  # True se salvato da "Configura Ruote" (manuale)
        self.udp_mode = tk.BooleanVar(value=False) # Switch Hex/UDP
        self.speed_var = tk.IntVar(value=50) # Valore default velocità
        
        self.hex_input_str = tk.StringVar()

        # Calibrazione: Salva gli angoli per ogni direzione
        self.poses = {
            "REST": {},  # Posizione di riposo
            "UP": {},
            "RIGHT": {},
            "LEFT": {}
        }

        # --- XBOX (XInput-Python) ---
        self.xbox_running = True
        self.last_xbox_y = 0.0
        
        # --- DA AGGIUNGERE IN App.__init__ ---
        self.joy_mapping = {}         # Es: {"BTN_A": {"id": 6, "type": 6}, "AXIS_LX": {"id": 1, "type": 1}}
        self.gripper_states = {}      # Es: {6: 0} (0=chiuso, 1=aperto)
        self.button_prev_state = {}   # Es: {"BTN_A_6": False} per edge detection

        self.joy_base_angles = {}
        self.joy_last_sent_values = {}
        self.joy_incremental_accumulators = {}
        self.joy_servo_speed = tk.DoubleVar(value=50.0)

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_app_close)
        if XInput:
            threading.Thread(target=self._monitor_xbox, daemon=True).start()
        else:
            print("[WARN] Libreria XInput-Python non installata.")
        self._apply_language(force=True)
        self.after(50, self._drain_log_queue)
        self.after(1200, self._auto_apply_language)
        # Delay breve: assicura che la finestra principale sia mappata prima del popup modale.
        self.after(120, self._show_disclaimer_popup)

    def _install_messagebox_i18n(self):
        if getattr(messagebox, "_clicbot_i18n_wrapped", False):
            return

        def _wrap(fn):
            def _inner(*args, **kwargs):
                a = list(args)
                if len(a) >= 1 and isinstance(a[0], str):
                    a[0] = self._tr(a[0])
                if len(a) >= 2 and isinstance(a[1], str):
                    a[1] = self._tr(a[1])
                if isinstance(kwargs.get("title"), str):
                    kwargs["title"] = self._tr(kwargs["title"])
                if isinstance(kwargs.get("message"), str):
                    kwargs["message"] = self._tr(kwargs["message"])
                return fn(*a, **kwargs)
            return _inner

        messagebox.showerror = _wrap(messagebox.showerror)
        messagebox.showwarning = _wrap(messagebox.showwarning)
        messagebox.showinfo = _wrap(messagebox.showinfo)
        messagebox._clicbot_i18n_wrapped = True

    def _build_translations(self):
        return {
            "Connessione": "Connection",
            "Porta:": "Port:",
            "Controllo e Strumenti": "Controls and Tools",
            "Entra mod. Assemblaggio": "Enter Assembly Mode",
            "Esci mod. Assemblaggio": "Exit Assembly Mode",
            "Invia MINI 03E3 (ping)": "Send MINI 03E3 (ping)",
            "Mostra JSON": "Show JSON",
            "Salva JSONâ€¦": "Save JSON...",
            "Salva JSON…": "Save JSON...",
            "Moduli riconosciutiâ€¦": "Detected Modules...",
            "Moduli riconosciuti…": "Detected Modules...",
            "Upload ZIP (protocollo sniff: 0x000d/0x000d)": "Upload ZIP (sniff protocol: 0x000d/0x000d)",
            "Scegli ZIPâ€¦": "Choose ZIP...",
            "Scegli ZIP…": "Choose ZIP...",
            "Avvia WebSocket": "Start WebSocket",
            "Ferma WebSocket": "Stop WebSocket",
            "Spento": "Off",
            "Non disponibile": "Unavailable",
            "Pronto. Inserisci IP e premi Connect + Handshake.\n": "Ready. Enter IP and press Connect + Handshake.\n",
            "Invia HEX Raw (Debug)": "Send Raw HEX (Debug)",
            "INVIA RAW": "SEND RAW",
            "Log": "Log",
            "Errore": "Error",
            "Errore Formato": "Format Error",
            "Errore Invio": "Send Error",
            "Non sei connesso!": "Not connected!",
            "Devi essere connesso per catturare le pose.": "You must be connected to capture poses.",
            "La stringa non Ã¨ un HEX valido.\nControlla di aver copiato solo caratteri 0-9, A-F.": "The string is not valid HEX.\nCheck that it only contains 0-9 and A-F.",
            "La stringa non è un HEX valido.\nControlla di aver copiato solo caratteri 0-9, A-F.": "The string is not valid HEX.\nCheck that it only contains 0-9 and A-F.",
            "Handshake": "Handshake",
            "Re-send Handshake": "Re-send Handshake",
            "Disconnect": "Disconnect",
            "Connect + Handshake": "Connect + Handshake",
            "SSH tool": "SSH tool",
            "Upload ZIP": "Upload ZIP",
            "Play": "Play",
            "Stop": "Stop",
            "Porta WS:": "WS Port:",
            "IP Robot:": "Robot IP:",
            "Nessun modulo.": "No modules.",
            "Nessuna struttura ancora ricevuta (03E9).": "No structure received yet (03E9).",
            "Moduli riconosciuti": "Detected modules",
            "Disclaimer": "Disclaimer",
            "Dichiarazione di esclusione di responsabilita'": "Liability Disclaimer",
            "Accetto": "Accept",
            "Non accetto": "Decline",
            "ClicBot Animation Studio - Multi Action Editor": "ClicBot Animation Studio - Multi Action Editor",
            "Programmazione Direzioni (Snapshot)": "Direction Programming (Snapshot)",
            "Configurazione Guida": "Drive Configuration",
            "Usa ModalitÃ  UDP (Script)": "Use UDP Mode (Script)",
            "Usa Modalità UDP (Script)": "Use UDP Mode (Script)",
            "Configurazione Ruote": "Wheel Configuration",
            "Configura Lato e Polarità:": "Configure Side and Polarity:",
            "Nessuna ruota trovata.\nFai prima Connect!": "No wheels found.\nConnect first!",
            "Salva Configurazione": "Save Configuration",
            "Concludi e Salva": "Finish and Save",
            "Programma SU, DX e SX. Poi premi Salva.": "Program UP, RIGHT and LEFT. Then press Save.",
            "💾 Salva": "💾 Save",
            "🧾 Mostra JSON direzioni": "🧾 Show Direction JSON",
            "💾 SALVA": "💾 SAVE",
            "Ruote (segno+vel)": "Wheels (sign+speed)",
            "Pronto.": "Ready.",
            "🕹️ Joystick & Programmazione": "🕹️ Joystick & Programming",
            "Ultimo JSON (STRUCTURE / 03E9)": "Latest JSON (STRUCTURE / 03E9)",
            "Salva…": "Save...",
            "Stato Robot": "Robot Status",
            "MODALITÃ€ GUIDA: SPENTA": "DRIVE MODE: OFF",
            "MODALITÃ€ GUIDA: ATTIVA": "DRIVE MODE: ON",
            "MODALITÀ GUIDA: SPENTA": "DRIVE MODE: OFF",
            "MODALITÀ GUIDA: ATTIVA": "DRIVE MODE: ON",
            "ATTIVA GUIDA (0x03)": "ENABLE DRIVE (0x03)",
            "DISATTIVA (0x02)": "DISABLE (0x02)",
            "Animation Studio": "Animation Studio",
            "Keepalive (ms):": "Keepalive (ms):",
            "Language:": "Language:",
            "Lingua:": "Language:",
            "WebSocket Bridge": "WebSocket Bridge",
            "Upload": "Upload",
            "Salva JSONâ€¦": "Save JSON...",
            "⚙ Configura Ruote": "⚙ Configure Wheels",
            "Guida Analogica (Richiede attivazione sopra)": "Analog Drive (Requires activation above)",
            "Modalità Joystick": "Joystick Mode",
            "Modalità Incrementale": "Incremental Mode",
            "Salva Attuale": "Save Current",
            "Salva e Esci": "Save and Exit",
            "SSH: inietta public key / abilita sshd": "SSH: inject public key / enable sshd",
            "abilita ssh": "enable ssh",
            "Chiave (-i):": "Key (-i):",
            "Cartella remota:": "Remote folder:",
            "Seleziona un'azione 'volante' (actType=2) nella lista.": "Select a steering action (actType=2) in the list.",
            "JSON Direzioni (volante)": "Direction JSON (steering)",
            "Mostra il JSON (formattato) della direzione/volante selezionata (actType=2).": "Show the formatted JSON of the selected direction/steering action (actType=2).",
            "Pronto.\n- 'inietta publikey' prepara /root/.ssh/authorized_keys e riavvia sshd\n- 'abilita ssh' avvia solo /usr/sbin/sshd\n- 'Dump (scp -r)' scarica la cartella remota su PC\n\n": "Ready.\n- 'inject pubkey' prepares /root/.ssh/authorized_keys and restarts sshd\n- 'enable ssh' starts only /usr/sbin/sshd\n- 'Dump (scp -r)' downloads the remote folder to PC\n\n",
            "Nuovo volante": "New Steering Action",
            "Crea / programma un nuovo volante": "Create / program a new steering action",
            "Nome:": "Name:",
            "⬆️ SU": "⬆️ UP",
            "➡️ DX": "➡️ RIGHT",
            "⬅️ SX": "⬅️ LEFT",
            "Annulla": "Cancel",
            "Lista Movimenti (Actions)": "Motion List (Actions)",
            "➕ Aggiungi": "➕ Add",
            "🗑 Elimina": "🗑 Delete",
            "🛞 Nuovo volante": "🛞 New Steering Action",
            "▶️ RIPRODUCI SELEZIONATO": "▶️ PLAY SELECTED",
            "Dettagli & Slot": "Details & Slot",
            "Slot ID:": "Slot ID:",
            "Aggiungi Step": "Add Step",
            "📸 CATTURA POSA": "📸 CAPTURE POSE",
            "📂 IMPORTA": "📂 IMPORT",
            "Inizializzazione...": "Initializing...",
            "Timeline": "Timeline",
            "Exec(s) ✎": "Exec(s) ✎",
            "Min(s)": "Min(s)",
            "Delay(s) ✎": "Delay(s) ✎",
            "Dettagli Angoli": "Angle Details",
            "Direzione": "Direction",
            "Giunti": "Joints",
            "Posa singola eseguita (Fast Mode).": "Single pose executed (Fast Mode).",
            "Fine.": "Done.",
            "JSON Direzioni": "Direction JSON",
            "Copia": "Copy",
            "Aggiorna": "Refresh",
            "ClicBot V3 - Programming & Drive (Dynamic)": "ClicBot - Programming & Drive (Dynamic)",
            "📍 Imposta Struttura (Zero)": "📍 Set Structure (Zero)",
            "🎮 Mappa Controller": "🎮 Controller Mapping",
            "Velocità Massima (Moltiplicatore)": "Max Speed (Multiplier)",
            "PROGRAMMA RIPOSO (REST)": "PROGRAM REST (REST)",
            "PROGRAMMA SU": "PROGRAM UP",
            "PROGRAMMA SX": "PROGRAM LEFT",
            "PROGRAMMA DX": "PROGRAM RIGHT",
            "mIndex": "mIndex",
            "Modulo": "Module",
            "Opzioni": "Options",
            "Blocca tutte le sfere": "Lock all joints",
            "Sblocca tutte": "Unlock all",
            "💡 Blink": "💡 Blink",
            "angolo:": "angle:",
            "bloccata": "locked",
            "(opzioni in arrivo)": "(options coming soon)",
            "🔓 Sblocca": "🔓 Unlock",
            "Attivo: La leva fa da acceleratore.\nRilascio: Il motore resta in posizione.": "Active: the stick works as accelerator.\nRelease: motor keeps its position.",
            "Limite Minimo": "Minimum Limit",
            "Limite Massimo": "Maximum Limit",
            "Reset Tutto": "Reset All",
            "Mappatura Controller COMPLETA": "Full Controller Mapping",
            "Impostazioni Globali Mappatura": "Global Mapping Settings",
            "Velocità Incrementale Servi:": "Servo Incremental Speed:",
            "[Manca controller.png]": "[controller.png missing]",
            "Public key (.pub):": "Public key (.pub):",
            "inietta publikey": "inject pubkey",
            "(usa nc verso porta 2222; IP preso dalla schermata principale)": "(uses nc to port 2222; IP taken from main screen)",
            "Dump via SCP": "Dump via SCP",
            "Porta SSH:": "SSH Port:",
            "Destinazione locale:": "Local destination:",
            "Log SSH tool": "SSH Tool Log",
            "Info": "Info",
            "Err": "Error",
            "Volante": "Steering",
            "Moduli": "Modules",
            "Già connesso.": "Already connected.",
            "Salvato.": "Saved.",
            "Scegli prima uno ZIP.": "Choose a ZIP first.",
            "Non sei connesso.": "Not connected.",
            "Nessun modulo rilevato! Fai Connect prima.": "No modules detected! Connect first.",
            "fileType:": "fileType:",
            "mapNumber:": "mapNumber:",
            "mapAngle:": "mapAngle:",
            "Attivo su :": "Active on :",
            "Attivazione Licenza": "License Activation",
            "Attivazione richiesta": "Activation required",
            "Questa copia deve essere attivata con una chiave firmata e legata al MAC address del PC.": "This copy must be activated with a signed key bound to this PC MAC address.",
            "Machine ID principale:": "Primary Machine ID:",
            "ID macchina (candidati):": "Machine IDs (candidates):",
            "Chiave di attivazione:": "Activation key:",
            "Copia ID": "Copy ID",
            "Attiva": "Activate",
            "Esci": "Exit",
            "Inserisci una chiave valida per continuare.": "Enter a valid key to continue.",
            "Nessun MAC valido trovato su questo sistema.": "No valid MAC found on this system.",
            "ID macchina copiato negli appunti.": "Machine ID copied to clipboard.",
            "Impossibile verificare la chiave: backend crittografico non disponibile.": "Unable to verify key: cryptographic backend not available.",
            "Chiave pubblica di licenza non valida.": "Invalid license public key.",
            "Errore lettura chiave pubblica.": "Error reading public key.",
            "Formato chiave non valido.": "Invalid key format.",
            "Firma della chiave non valida.": "Invalid key signature.",
            "Payload chiave non valido.": "Invalid key payload.",
            "La chiave non appartiene a questo PC.": "This key does not belong to this PC.",
            "Formato data di scadenza non valido.": "Invalid expiration date format.",
            "Licenza scaduta.": "License expired.",
            "Licenza valida.": "License valid.",
            "Chiave di attivazione non valida.": "Invalid activation key.",
            "Attivazione completata con successo.": "Activation completed successfully.",
        }

    def _tr(self, text):
        if not isinstance(text, str):
            return text

        variants = [text]
        # Try to recover mojibake variants generated by encoding mismatches.
        for enc in ("latin1", "cp1252"):
            try:
                fixed = text.encode(enc, errors="ignore").decode("utf-8", errors="ignore")
                if fixed and fixed not in variants:
                    variants.append(fixed)
            except Exception:
                pass

        if self._lang_code == "en":
            for t in variants:
                if t in self._it_to_en:
                    return self._it_to_en[t]
            if text.startswith("Attivo su :"):
                return "Active on :" + text[len("Attivo su :"):]
            return text
        for t in variants:
            if t in self._en_to_it:
                return self._en_to_it[t]
        if text.startswith("Active on :"):
            return "Attivo su :" + text[len("Active on :"):]
        return text

    def _translate_widget_tree(self, w):
        try:
            if isinstance(w, (tk.Tk, tk.Toplevel)):
                t = w.title()
                nt = self._tr(t)
                if nt != t:
                    w.title(nt)
        except Exception:
            pass

        try:
            keys = w.keys() if hasattr(w, "keys") else []
            if "text" in keys:
                txt = w.cget("text")
                ntxt = self._tr(txt)
                if ntxt != txt:
                    w.config(text=ntxt)
        except Exception:
            pass

        # Treeview headings are not part of widget "text" and need explicit translation.
        try:
            if isinstance(w, ttk.Treeview):
                cols = ["#0"] + list(w.cget("columns"))
                for c in cols:
                    htxt = w.heading(c).get("text", "")
                    nhtxt = self._tr(htxt)
                    if nhtxt != htxt:
                        w.heading(c, text=nhtxt)
        except Exception:
            pass

        for ch in w.winfo_children():
            self._translate_widget_tree(ch)

    def _on_language_changed(self, *_):
        self._apply_language(force=True)

    def _apply_language(self, force=False):
        selected = (self.lang_var.get() or "").strip().lower()
        new_code = "it" if selected.startswith("ital") else "en"
        if not force and new_code == self._lang_code:
            return
        self._lang_code = new_code
        try:
            if hasattr(self, "lbl_lang"):
                self.lbl_lang.config(text=self._tr("Language:"))
            if hasattr(self, "cmb_lang"):
                self.cmb_lang.configure(values=("English", "Italiano"))
        except Exception:
            pass
        self._translate_widget_tree(self)

    def _auto_apply_language(self):
        try:
            self._apply_language(force=True)
        finally:
            self.after(1200, self._auto_apply_language)

    def _apply_app_icon(self):
        """Imposta l'icona app da file locale (preferenza .ico, fallback .png)."""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        icon_ico = os.path.join(base_dir, "app_icon.ico")
        icon_png = os.path.join(base_dir, "app_icon.png")

        try:
            if os.path.isfile(icon_ico):
                self.iconbitmap(icon_ico)
        except Exception:
            pass

        try:
            if os.path.isfile(icon_png):
                self._app_icon_img = tk.PhotoImage(file=icon_png)
                self.iconphoto(True, self._app_icon_img)
        except Exception:
            pass

    # ---------- Activation / Licensing ----------
    def _app_base_dir(self):
        try:
            if getattr(sys, "frozen", False):
                return os.path.dirname(os.path.abspath(sys.argv[0]))
        except Exception:
            pass
        return os.path.dirname(os.path.abspath(__file__))

    def _license_public_key_path(self):
        return os.path.join(self._app_base_dir(), "license_public.pem")

    def _license_storage_path(self):
        appdata = os.getenv("APPDATA") or os.path.expanduser("~")
        lic_dir = os.path.join(appdata, "ClicBotDevTools")
        try:
            os.makedirs(lic_dir, exist_ok=True)
        except Exception:
            pass
        return os.path.join(lic_dir, "license.json")

    def _normalize_mac(self, raw: str):
        if not raw:
            return None
        h = "".join(ch for ch in str(raw) if ch.lower() in "0123456789abcdef")
        if len(h) != 12:
            return None
        h = h.upper()
        if h == "000000000000":
            return None
        return h

    def _collect_mac_addresses(self):
        macs = set()

        try:
            node = int(uuid.getnode())
            mac = self._normalize_mac(f"{node:012x}")
            if mac:
                macs.add(mac)
        except Exception:
            pass

        try:
            out = subprocess.check_output(
                ["getmac", "/fo", "csv", "/nh"],
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            for line in out.splitlines():
                parts = [p.strip().strip('"') for p in line.split(",")]
                if not parts:
                    continue
                mac = self._normalize_mac(parts[0])
                if mac:
                    macs.add(mac)
        except Exception:
            pass

        return sorted(macs)

    def _machine_id_candidates(self):
        macs = self._collect_mac_addresses()
        ids = []
        if macs:
            combined_src = "|".join(macs).encode("ascii")
            combined = hashlib.sha256(combined_src).hexdigest()[:20].upper()
            ids.append(f"{LICENSE_TOKEN_PREFIX}-C-{combined}")

        for mac in macs:
            mid = hashlib.sha256(mac.encode("ascii")).hexdigest()[:20].upper()
            ids.append(f"{LICENSE_TOKEN_PREFIX}-M-{mid}")

        return ids, macs

    def _load_public_key(self):
        if Ed25519PublicKey is None:
            return None, self._tr("Impossibile verificare la chiave: backend crittografico non disponibile.")

        path = self._license_public_key_path()
        if os.path.isfile(path) and serialization is not None:
            try:
                with open(path, "rb") as f:
                    pem = f.read()
                k = serialization.load_pem_public_key(pem)
                if isinstance(k, Ed25519PublicKey):
                    return k, None
                return None, self._tr("Chiave pubblica di licenza non valida.")
            except Exception:
                return None, self._tr("Errore lettura chiave pubblica.")

        try:
            return Ed25519PublicKey.from_public_bytes(bytes.fromhex(DEFAULT_LICENSE_PUBKEY_HEX)), None
        except Exception:
            return None, self._tr("Chiave pubblica di licenza non valida.")

    def _verify_activation_key(self, token: str):
        token = (token or "").strip()
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != LICENSE_TOKEN_PREFIX:
            return False, self._tr("Formato chiave non valido."), None

        try:
            payload_bytes = _b64u_decode(parts[1])
            sig = _b64u_decode(parts[2])
        except Exception:
            return False, self._tr("Formato chiave non valido."), None

        pub, err = self._load_public_key()
        if pub is None:
            return False, err or self._tr("Chiave pubblica di licenza non valida."), None

        try:
            pub.verify(sig, payload_bytes)
        except Exception:
            return False, self._tr("Firma della chiave non valida."), None

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return False, self._tr("Payload chiave non valido."), None

        machine_id = str(payload.get("machine_id", "")).strip().upper()
        ids, _ = self._machine_id_candidates()
        if not machine_id or machine_id not in ids:
            return False, self._tr("La chiave non appartiene a questo PC."), None

        expires = str(payload.get("expires_at", "") or "").strip()
        if expires:
            try:
                exp_date = datetime.date.fromisoformat(expires)
            except Exception:
                return False, self._tr("Formato data di scadenza non valido."), None
            if datetime.date.today() > exp_date:
                return False, self._tr("Licenza scaduta."), None

        return True, self._tr("Licenza valida."), payload

    def _load_saved_activation_key(self):
        path = self._license_storage_path()
        if not os.path.isfile(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return str(data.get("activation_key", "")).strip()
        except Exception:
            return ""

    def _save_activation_key(self, token: str, payload: dict):
        path = self._license_storage_path()
        data = {
            "activation_key": token,
            "saved_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "machine_id": str(payload.get("machine_id", "")),
            "owner": str(payload.get("owner", "")),
            "expires_at": str(payload.get("expires_at", "")),
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _show_activation_popup(self):
        if self._activation_ok:
            return

        saved = self._load_saved_activation_key()
        if saved:
            ok, _, _payload = self._verify_activation_key(saved)
            if ok:
                self._activation_ok = True
                return

        machine_ids, _macs = self._machine_id_candidates()
        primary_id = machine_ids[0] if machine_ids else f"{LICENSE_TOKEN_PREFIX}-NO-MAC"

        win = tk.Toplevel(self)
        win.title(self._tr("Attivazione Licenza"))
        w, h = 700, 430
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.resizable(False, False)
        win.transient(self)
        try:
            win.attributes("-topmost", True)
        except Exception:
            pass
        win.grab_set()
        win.focus_force()

        frm = ttk.Frame(win, padding=14)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text=self._tr("Attivazione richiesta"), font=("Arial", 12, "bold")).pack(anchor="w")
        ttk.Label(
            frm,
            text=self._tr("Questa copia deve essere attivata con una chiave firmata e legata al MAC address del PC."),
            wraplength=660,
            justify="left",
        ).pack(anchor="w", pady=(6, 10))

        ttk.Label(frm, text=self._tr("Machine ID principale:")).pack(anchor="w")
        id_var = tk.StringVar(value=primary_id)
        ttk.Entry(frm, textvariable=id_var, state="readonly").pack(fill="x", pady=(2, 8))

        ttk.Label(frm, text=self._tr("ID macchina (candidati):")).pack(anchor="w")
        id_list = tk.Text(frm, height=4, wrap="none")
        id_list.pack(fill="x", pady=(2, 8))
        if machine_ids:
            id_list.insert("1.0", "\n".join(machine_ids))
        else:
            id_list.insert("1.0", self._tr("Nessun MAC valido trovato su questo sistema."))
        id_list.config(state="disabled")

        ttk.Label(frm, text=self._tr("Chiave di attivazione:")).pack(anchor="w")
        key_var = tk.StringVar(value=saved or "")
        ttk.Entry(frm, textvariable=key_var).pack(fill="x", pady=(2, 6))

        status_var = tk.StringVar(value=self._tr("Inserisci una chiave valida per continuare."))
        ttk.Label(frm, textvariable=status_var, foreground="#a33").pack(anchor="w", pady=(0, 6))

        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(8, 0))

        def _copy_id():
            try:
                self.clipboard_clear()
                self.clipboard_append(primary_id)
                status_var.set(self._tr("ID macchina copiato negli appunti."))
            except Exception:
                pass

        def _activate():
            token = key_var.get().strip()
            ok, msg, payload = self._verify_activation_key(token)
            if not ok:
                status_var.set(msg or self._tr("Chiave di attivazione non valida."))
                return
            self._save_activation_key(token, payload or {})
            self._activation_ok = True
            try:
                win.grab_release()
            except Exception:
                pass
            win.destroy()
            self.lift()
            self.focus_force()
            messagebox.showinfo(self._tr("Info"), self._tr("Attivazione completata con successo."))

        def _exit_app():
            try:
                win.grab_release()
            except Exception:
                pass
            self._on_app_close()

        ttk.Button(btns, text=self._tr("Copia ID"), command=_copy_id).pack(side="left")
        ttk.Button(btns, text=self._tr("Esci"), command=_exit_app).pack(side="right")
        ttk.Button(btns, text=self._tr("Attiva"), command=_activate).pack(side="right", padx=(0, 6))
        win.protocol("WM_DELETE_WINDOW", _exit_app)

    def _on_app_close(self):
        self.xbox_running = False
        try:
            self.stop_ws()
        except Exception:
            pass
        try:
            if self.sock:
                self.disconnect()
        except Exception:
            pass
        self.destroy()

    def _show_disclaimer_popup(self):
        """Popup obbligatorio all'avvio: accetta per continuare, altrimenti chiude l'app."""
        win = tk.Toplevel(self)
        win.title(self._tr("Disclaimer"))
        w, h = 640, 360
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.resizable(False, False)
        win.transient(self)
        try:
            win.attributes("-topmost", True)
        except Exception:
            pass
        win.grab_set()
        win.focus_force()

        frm = ttk.Frame(win, padding=14)
        frm.pack(fill="both", expand=True)

        ttk.Label(
            frm,
            text=self._tr("Liability Disclaimer"),
            font=("Arial", 12, "bold")
        ).pack(anchor="w", pady=(0, 8))

        if self._lang_code == "it":
            disclaimer_text = (
                "Utilizzando questa applicazione, l'utente dichiara di farne uso sotto la "
                "propria esclusiva responsabilita'.\n\n"
                "Lo sviluppatore non e' responsabile per danni diretti o indiretti, perdita "
                "di dati, malfunzionamenti, uso improprio, violazioni normative o qualsiasi "
                "conseguenza derivante dall'uso del software.\n\n"
                "Se non accetti questi termini, seleziona 'Non accetto' per chiudere "
                "immediatamente l'app."
            )
        else:
            disclaimer_text = (
                "By using this application, you agree that you do so at your own sole risk.\n\n"
                "The developer is not responsible for direct or indirect damages, data loss, "
                "malfunctions, misuse, regulatory violations, or any consequences resulting "
                "from the use of this software.\n\n"
                "If you do not accept these terms, select 'Decline' to close the app immediately."
            )

        txt = tk.Text(frm, height=11, wrap="word")
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", disclaimer_text)
        txt.config(state="disabled")

        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(10, 0))

        def _accept():
            try:
                win.grab_release()
            except Exception:
                pass
            win.destroy()
            self.lift()
            self.focus_force()
            self.after(50, self._show_activation_popup)

        def _decline():
            try:
                win.grab_release()
            except Exception:
                pass
            self._on_app_close()

        ttk.Button(btns, text=self._tr("Accept"), command=_accept).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text=self._tr("Decline"), command=_decline).pack(side="right")
        win.protocol("WM_DELETE_WINDOW", _decline)
    
    def send_raw_hex_from_ui(self):
        """Prende la stringa dalla GUI, la converte in bytes e la invia così com'è."""
        if not self.sock:
            messagebox.showerror(self._tr("Errore"), self._tr("Non sei connesso!"))
            return
            
        raw_str = self.hex_input_str.get().strip()
        if not raw_str: return

        # 1. Pulizia: Rimuove spazi, '0x', a capo, ecc.
        clean_str = raw_str.replace(" ", "").replace("0x", "").replace("\n", "").replace("\r", "")
        
        try:
            # 2. Conversione in Bytes
            payload = bytes.fromhex(clean_str)
            
            # 3. Invio diretto (Senza aggiungere header, perché la stringa è già completa)
            self._tx(payload, note="[RAW HEX MANUAL]")
            self._log(f"[DEBUG] Inviato manuale: {clean_str[:30]}... ({len(payload)} bytes)\n")
            
        except ValueError:
            messagebox.showerror(self._tr("Errore Formato"), self._tr("La stringa non è un HEX valido.\nControlla di aver copiato solo caratteri 0-9, A-F."))
        except Exception as e:
            messagebox.showerror(self._tr("Errore Invio"), str(e))

    def send_play_cmd(self):
        """Invia il comando play."""
        if not self.sock:
            messagebox.showerror(self._tr("Errore"), self._tr("Non sei connesso!"))
            return
        self._tx(bytes.fromhex("67001b00020000006600"), note="PLAY 67001b00020000006600")

    def send_stop_cmd(self):
        """Invia il comando stop."""
        if not self.sock:
            messagebox.showerror(self._tr("Errore"), self._tr("Non sei connesso!"))
            return
        self._tx(bytes.fromhex("67000f00020000006500"), note="STOP 67000f00020000006500")

    def apply_volante_action_to_drive(self, volante_action: dict):
        """Applica un'azione volante (actType=2) alle pose di guida (UP/LEFT/RIGHT) usate dalla schermata Joystick."""
        try:
            if not volante_action or int(volante_action.get("actType", 0) or 0) != 2:
                return
        except Exception:
            return

        steps = volante_action.get("STEP", []) or []
        # Mappa fissa: stepIndex 1/2 = UP, 3 = RIGHT, 4 = LEFT (come robot.json originale)
        pose_map = {"UP": None, "RIGHT": None, "LEFT": None}

        for s in steps:
            try:
                si = int(s.get("stepIndex", 0))
            except Exception:
                continue
            if si in (1, 2):
                key = "UP"
            elif si == 3:
                key = "RIGHT"
            elif si == 4:
                key = "LEFT"
            else:
                continue

            post = s.get("POSTURE", []) or []
            p = {}
            for it in post:
                try:
                    if int(it.get("type", 0)) == 1:
                        mid = int(it.get("moduleId", 0))
                        p[mid] = float(it.get("angle", 0.0))
                except Exception:
                    pass
            if p:
                pose_map[key] = p

        # Applica se presenti
        for k in ("UP", "RIGHT", "LEFT"):
            if pose_map.get(k):
                self.poses[k] = pose_map[k]


    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        # Connessione
        top = ttk.LabelFrame(frm, text="Connessione")
        top.pack(fill="x")
        ttk.Label(top, text="IP Robot:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.ip_var = tk.StringVar(value="192.168.1.117")
        ttk.Entry(top, textvariable=self.ip_var, width=18).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        ttk.Label(top, text="Porta:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.port_var = tk.IntVar(value=9632)
        ttk.Entry(top, textvariable=self.port_var, width=8).grid(row=0, column=3, sticky="w", padx=5, pady=5)
        ttk.Label(top, text="Keepalive (ms):").grid(row=0, column=4, sticky="w", padx=5, pady=5)
        self.keepalive_ms = tk.IntVar(value=5000)
        ttk.Entry(top, textvariable=self.keepalive_ms, width=8).grid(row=0, column=5, sticky="w", padx=5, pady=5)
        self.lbl_lang = ttk.Label(top, text="Language:")
        self.lbl_lang.grid(row=0, column=6, sticky="w", padx=(10, 5), pady=5)
        self.cmb_lang = ttk.Combobox(top, textvariable=self.lang_var, values=("English", "Italiano"), state="readonly", width=10)
        self.cmb_lang.grid(row=0, column=7, sticky="w", padx=5, pady=5)
        self.cmb_lang.bind("<<ComboboxSelected>>", self._on_language_changed)

                # Pulsanti a destra (Disconnect + SSH tool)
        btns = ttk.Frame(top)
        btns.grid(row=0, column=8, columnspan=3, sticky="e", padx=8, pady=5)
        top.grid_columnconfigure(8, weight=1)

        self.btn_connect = ttk.Button(btns, text="Connect + Handshake", command=self.connect_and_handshake)
        self.btn_connect.pack(side="left", padx=(0, 8))

        self.btn_disconnect = ttk.Button(btns, text="Disconnect", command=self.disconnect, state="disabled")
        self.btn_disconnect.pack(side="left", padx=(0, 8))

        self.btn_ssh_tool = ttk.Button(btns, text="SSH tool", command=self.open_ssh_tool_window)
        self.btn_ssh_tool.pack(side="left")

        # Handshake params
        hs = ttk.LabelFrame(frm, text="Handshake")
        hs.pack(fill="x", pady=10)
        ttk.Label(hs, text="deviceName:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.devname_var = tk.StringVar(value="PC-Python")
        ttk.Entry(hs, textvariable=self.devname_var, width=18).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        ttk.Label(hs, text="userName:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.username_var = tk.StringVar(value="PythonClient")
        ttk.Entry(hs, textvariable=self.username_var, width=18).grid(row=0, column=3, sticky="w", padx=5, pady=5)
        ttk.Label(hs, text="deviceToken:").grid(row=0, column=4, sticky="w", padx=5, pady=5)
        self.token_var = tk.StringVar(value="")
        ttk.Entry(hs, textvariable=self.token_var, width=36).grid(row=0, column=5, sticky="w", padx=5, pady=5)
        self.btn_handshake = ttk.Button(hs, text="Re-send Handshake", command=self._do_handshake, state="disabled")
        self.btn_handshake.grid(row=0, column=6, sticky="w", padx=8, pady=5)

        # Moduli / Assembly / NUOVO JOYSTICK
        mods = ttk.LabelFrame(frm, text="Controllo e Strumenti")
        mods.pack(fill="x", pady=5)
        for col in range(4):
            mods.grid_columnconfigure(col, weight=1)

        self.btn_assembly = ttk.Button(mods, text="Entra mod. Assemblaggio", command=self.enter_assembly_mode, state="disabled")
        self.btn_assembly.grid(row=0, column=0, padx=8, pady=8, sticky="w")
            
        # Pulsante ESCI (Nuovo)
        self.btn_exit_assembly = ttk.Button(mods, text="Esci mod. Assemblaggio", command=self.exit_assembly_mode, state="disabled")
        self.btn_exit_assembly.grid(row=0, column=1, padx=5, pady=8, sticky="w")
        
        self.btn_ping = ttk.Button(mods, text="Invia MINI 03E3 (ping)", command=self.send_ping, state="disabled")
        self.btn_ping.grid(row=0, column=2, padx=8, pady=8, sticky="w")

        self.btn_show_json = ttk.Button(mods, text="Mostra JSON", command=self.show_last_structure_json, state="disabled")
        self.btn_show_json.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        self.btn_save_json = ttk.Button(mods, text="Salva JSON…", command=self.save_last_structure_json, state="disabled")
        self.btn_save_json.grid(row=1, column=0, padx=8, pady=8, sticky="w")

        self.btn_modules = ttk.Button(mods, text="Moduli riconosciuti…", command=self.show_modules_window, state="disabled")
        self.btn_modules.grid(row=1, column=1, padx=8, pady=8, sticky="w")

        # --- PULSANTE NUOVO PER JOYSTICK PROGRAMMATO ---
        self.btn_joy = ttk.Button(mods, text="🕹️ Joystick & Programmazione", command=self.open_joystick_window, state="normal")
        self.btn_joy.grid(row=1, column=3, padx=8, pady=8, sticky="w")
        
         # --- NUOVO BOTTONE ANIMATION STUDIO ---
        self.btn_anim = ttk.Button(mods, text="🎬 Animation Studio", command=self.open_animation_studio, state="disabled")
        self.btn_anim.grid(row=1, column=2, padx=8, pady=8, sticky="w")
        
        # Upload ZIP
        up = ttk.LabelFrame(frm, text="Upload ZIP (protocollo sniff: 0x000d/0x000d)")
        up.pack(fill="x", pady=10)
        self.zip_path = tk.StringVar(value="")
        ttk.Button(up, text="Scegli ZIP…", command=self.pick_zip).grid(row=0, column=0, padx=5, pady=8, sticky="w")
        ttk.Entry(up, textvariable=self.zip_path, width=74).grid(row=0, column=1, padx=5, pady=8, sticky="w")
        self.btn_upload = ttk.Button(up, text="Upload ZIP", command=self.upload_zip_sniff, state="disabled")
        self.btn_upload.grid(row=0, column=2, padx=10, pady=5, sticky="w")
        self.btn_play_zip = ttk.Button(up, text="Play", command=self.send_play_cmd, state="disabled")
        self.btn_play_zip.grid(row=0, column=3, padx=6, pady=5, sticky="w")
        self.btn_stop_zip = ttk.Button(up, text="Stop", command=self.send_stop_cmd, state="disabled")
        self.btn_stop_zip.grid(row=0, column=4, padx=6, pady=5, sticky="w")
        meta = ttk.Frame(up)
        meta.grid(row=1, column=0, columnspan=5, sticky="w", padx=5, pady=5)
        ttk.Label(meta, text="fileType:").grid(row=0, column=0, sticky="w")
        self.filetype_var = tk.IntVar(value=0)
        ttk.Entry(meta, textvariable=self.filetype_var, width=5).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(meta, text="mapNumber:").grid(row=0, column=2, sticky="w")
        self.mapnum_var = tk.StringVar(value='{"0":0,"1":1}')
        ttk.Entry(meta, textvariable=self.mapnum_var, width=18).grid(row=0, column=3, sticky="w", padx=5)
        ttk.Label(meta, text="mapAngle:").grid(row=0, column=4, sticky="w")
        self.mapang_var = tk.StringVar(value='{"0":0,"1":0}')
        ttk.Entry(meta, textvariable=self.mapang_var, width=18).grid(row=0, column=5, sticky="w", padx=5)

        # WebSocket Bridge
        ws = ttk.LabelFrame(frm, text="WebSocket Bridge")
        ws.pack(fill="x", pady=8)
        ttk.Label(ws, text="Porta WS:").grid(row=0, column=0, sticky="w", padx=5, pady=6)
        ttk.Entry(ws, textvariable=self.ws_port_var, width=8).grid(row=0, column=1, sticky="w", padx=5, pady=6)
        self.btn_ws = ttk.Button(ws, text="Avvia WebSocket", command=self.toggle_ws)
        self.btn_ws.grid(row=0, column=2, sticky="w", padx=8, pady=6)
        self.ws_status = ttk.Label(ws, text="Spento")
        self.ws_status.grid(row=0, column=3, sticky="w", padx=8, pady=6)

        # --- [NUOVO] DEBUG HEX RAW SENDER ---
        dbg = ttk.LabelFrame(frm, text="Invia HEX Raw (Debug)")
        dbg.pack(fill="x", pady=5)
        
        ttk.Label(dbg, text="HEX String:").pack(side="left", padx=5)
        
        # Casella di testo larga per incollare codici lunghi
        entry_hex = ttk.Entry(dbg, textvariable=self.hex_input_str)
        entry_hex.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        
        # Tasto Invio
        ttk.Button(dbg, text="INVIA RAW", command=self.send_raw_hex_from_ui).pack(side="right", padx=5)
        # ------------------------------------

        # Log
        logf = ttk.LabelFrame(frm, text="Log")
        logf.pack(fill="both", expand=True, pady=10)
        self.log = tk.Text(logf, height=15, wrap="none")
        self.log.pack(fill="both", expand=True)
        self._log(self._tr("Ready. Enter IP and press Connect + Handshake.\n"))

    # ---------- REINTEGRAZIONE FUNZIONI V3 MANCANTI (WebSocket) ----------
    def toggle_ws(self):
        if self.ws_enabled: self.stop_ws()
        else: self.start_ws()

    def start_ws(self):
        try: port = int(self.ws_port_var.get())
        except Exception:
            port = 8787
            self.ws_port_var.set(port)
        self.ws_bridge = WsBridge(port=port, log=self._log)
        self.ws_bridge.start()
        self.ws_enabled = True if self.ws_bridge._running else False
        if self.ws_enabled:
            self.ws_status.config(text=self._tr(f"Active on :{port}"))
            self.btn_ws.config(text=self._tr("Stop WebSocket"))
        else:
            self.ws_status.config(text=self._tr("Unavailable"))
            self.btn_ws.config(text=self._tr("Start WebSocket"))

    def stop_ws(self):
        try: self.ws_bridge.stop()
        except Exception: pass
        self.ws_enabled = False
        self.ws_status.config(text=self._tr("Off"))
        self.btn_ws.config(text=self._tr("Start WebSocket"))

    # ---------- REINTEGRAZIONE FUNZIONI V3 MANCANTI (JSON) ----------
    def open_animation_studio(self):
        if not self.sock:
            messagebox.showerror(self._tr("Errore"), self._tr("You must be connected to capture poses."))
            return
        # Apre la finestra
        AnimationStudioWindow(self, self)
    
    def _refresh_json_controls(self):
        # Stato base: connesso o no
        state_conn = "normal" if self.running else "disabled"
        
        try:
            # Il tasto Animation Studio si attiva appena connessi
            self.btn_anim.config(state=state_conn)
        except: pass

        # LOGICA CORRETTA:
        # Attiva i tasti JSON se:
        # 1. Siamo in modalità assemblaggio (is_assembly)
        # 2. OPPURE abbiamo ricevuto dei dati validi (_structure_json non è vuoto)
        # 3. E ovviamente dobbiamo essere connessi (self.running)
        
        is_assembly = getattr(self, "_assembly_active", False)
        has_data = self._structure_json is not None
        
        state_json = "normal" if self.running and (is_assembly or has_data) else "disabled"
        
        try:
            self.btn_show_json.config(state=state_json)
            self.btn_save_json.config(state=state_json)
            self.btn_modules.config(state=state_json)
        except Exception:
            pass

    def _update_json_window_text(self):
        if self._json_text_widget is None: return
        self._json_text_widget.delete("1.0", "end")
        self._json_text_widget.insert("end", self._last_structure_json_text or "(nessun JSON ancora ricevuto)")

    def show_last_structure_json(self):
        if self._json_win is not None and self._json_win.winfo_exists():
            self._json_win.lift()
            self._update_json_window_text()
            return
        win = tk.Toplevel(self)
        win.title("Ultimo JSON (STRUCTURE / 03E9)")
        win.geometry("720x600")
        self._json_win = win
        top = ttk.Frame(win, padding=8)
        top.pack(fill="x")
        ttk.Button(top, text="Aggiorna", command=self._update_json_window_text).pack(side="left")
        ttk.Button(top, text="Copia", command=self._copy_json_to_clipboard).pack(side="left", padx=6)
        ttk.Button(top, text="Salva…", command=self.save_last_structure_json).pack(side="left")
        txt = tk.Text(win, wrap="none")
        txt.pack(fill="both", expand=True)
        self._json_text_widget = txt
        self._update_json_window_text()
        def _on_close():
            self._json_win = None
            self._json_text_widget = None
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", _on_close)

    def _copy_json_to_clipboard(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(self._last_structure_json_text or "")
            self._log("[*] JSON copiato negli appunti.\n")
        except Exception:
            self._log("[!] Impossibile copiare JSON negli appunti.\n")

    def save_last_structure_json(self):
        if not self._last_structure_json_text:
            messagebox.showinfo("JSON", "Nessun JSON STRUCTURE ancora ricevuto.")
            return
        path = filedialog.asksaveasfilename(title="Salva JSON", defaultextension=".json", filetypes=[("JSON", "*.json"), ("Tutti i file", "*.*")])
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f: f.write(self._last_structure_json_text)
            self._log(f"[*] Salvato JSON: {path}\n")
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile salvare il JSON.\n\n{e}")

    # ---------- JOYSTICK / PROGRAMMING WINDOW ----------
    def open_joystick_window(self):
        win = tk.Toplevel(self)
        win.title("ClicBot V3 - Programming & Drive (Dynamic)")
        win.geometry("600x750")

        # --- SEZIONE CONTROLLO MODALITÀ ---
        mode_frame = ttk.LabelFrame(win, text="Stato Robot", padding=10)
        mode_frame.pack(fill="x", padx=10, pady=5)
        
        # Indicatore e Bottone
        self.lbl_drive_status = ttk.Label(mode_frame, text="MODALITÀ GUIDA: SPENTA", foreground="red", font=("Arial", 12, "bold"))
        self.lbl_drive_status.pack(side="left", padx=10)
        
        self.btn_drive_toggle = ttk.Button(mode_frame, text="ATTIVA GUIDA (0x03)", command=self._toggle_drive_mode)
        self.btn_drive_toggle.pack(side="right", padx=10)

        # --- UDP Toggle e Configurazione Ruote ---
        # 1. PRIMA creo il frame
        conf_frame = ttk.LabelFrame(win, text="Configurazione Guida")
        conf_frame.pack(fill="x", padx=10, pady=5)

        # 2. POI aggiungo i pulsanti dentro al frame
        ttk.Checkbutton(conf_frame, text="Usa Modalità UDP (Script)", variable=self.udp_mode).pack(side="left", padx=10)
        
        # [NUOVO BOTTONE QUI]
        ttk.Button(conf_frame, text="📍 Imposta Struttura (Zero)", 
                   command=self._set_structure_baseline).pack(side="left", padx=5)

        # Bottone Configura Ruote
        ttk.Button(conf_frame, text="⚙ Configura Ruote", command=lambda: WheelConfigWindow(win, self)).pack(side="right", padx=10)
        
        # Bottone Mappa Controller (NUOVO - POSIZIONE CORRETTA)
        ttk.Button(conf_frame, text="🎮 Mappa Controller", command=lambda: JoystickMapWindow(win, self)).pack(side="right", padx=10)

        # --- SLIDER VELOCITÀ ---
        spd_frame = ttk.LabelFrame(win, text="Velocità Massima (Moltiplicatore)")
        spd_frame.pack(fill="x", padx=10, pady=5)
        
        lbl_spd_val = ttk.Label(spd_frame, text=f"Valore: {self.speed_var.get()}")
        lbl_spd_val.pack(side="top")
        
        def _on_spd_change(v):
            val = int(float(v))
            self.speed_var.set(val)
            lbl_spd_val.config(text=f"Valore: {val}")
            
        scale = ttk.Scale(spd_frame, from_=1, to=100, variable=self.speed_var, command=_on_spd_change)
        scale.pack(fill="x", padx=10, pady=5)

        # Sezione Programmazione (Invariata)
        prog_frame = ttk.LabelFrame(win, text="Programmazione Direzioni (Snapshot)")
        prog_frame.pack(fill="x", padx=10, pady=10)
        
        # IMPORTANTE: Programma REST
        ttk.Button(prog_frame, text="PROGRAMMA RIPOSO (REST)", command=lambda: self._program_dir("REST")).pack(fill="x", padx=40, pady=5)
        
        btn_layout = ttk.Frame(prog_frame)
        btn_layout.pack(pady=10)
        ttk.Button(btn_layout, text="PROGRAMMA SU", command=lambda: self._program_dir("UP")).grid(row=0, column=1, pady=5)
        ttk.Button(btn_layout, text="PROGRAMMA SX", command=lambda: self._program_dir("LEFT")).grid(row=1, column=0, padx=10)
        ttk.Button(btn_layout, text="PROGRAMMA DX", command=lambda: self._program_dir("RIGHT")).grid(row=1, column=2, padx=10)

        # Sezione Guida (Joystick)
        drive_frame = ttk.LabelFrame(win, text="Guida Analogica (Richiede attivazione sopra)")
        drive_frame.pack(fill="both", expand=True, padx=10, pady=10)
        canvas = tk.Canvas(drive_frame, width=300, height=300, bg="#f9f9f9", highlightthickness=1)
        canvas.pack(pady=20)
        canvas.create_oval(50, 50, 250, 250, outline="#ccc", dash=(4,4))
        ball = canvas.create_oval(135, 135, 165, 165, fill="#ff5722")

        canvas.bind("<B1-Motion>", lambda event: self._on_joy_move(event, canvas, ball))
        canvas.bind("<ButtonRelease-1>", lambda event: self._on_joy_release(event, canvas, ball))
        
        # Aggiorna grafica pulsante all'apertura
        self._update_drive_btn_ui()
    
    def _set_structure_baseline(self):
        """
        1. Salva gli angoli attuali di tutti i SERVI come 'Base'.
        2. Invia un comando F003 BATCH per mantenere la posizione.
        """
        if not self.sock or not self._structure_by_index:
            print("[ERR] Non connesso o struttura non letta.")
            return

        self.joy_base_angles = {}
        payload = bytearray()
        
        # Recupera tutti gli ID ordinati
        ids = sorted(self._structure_by_index.keys())
        
        for mid in ids:
            node = self._structure_by_index[mid]
            m_type = node.get("type", 0)
            
            raw_angle = 0
            
            # Se è un Servo (Type 1), leggiamo l'angolo attuale
            if m_type == 1:
                deg = float(node.get("angle", 0.0))
                # Conversione Gradi -> Raw (0-4096)
                raw_angle = int((deg % 360.0) / 360.0 * 4096.0) & 0xFFFF
                # Salviamo in memoria per il joystick
                self.joy_base_angles[mid] = raw_angle
            else:
                # Per ruote o altro, angolo 0 come richiesto
                raw_angle = 0
                # Opzionale: self.joy_base_angles[mid] = 0
            
            # Costruzione Payload: [ID] [Mode=02] [Time=50ms] [RawLo] [RawHi]
            # Time 50ms = 0x0032
            payload.extend(struct.pack("<BBHH", mid, 0x02, 50, raw_angle))

        # Invio pacchetto Batch F003
        self._tx(pack_std(0x03F0, self._next_cmd(), payload), "Set Structure (Batch F0)")
        print(f"[INFO] Struttura Impostata! Base Angles: {len(self.joy_base_angles)} servi.")
        
        # --- LOGICA CONFIGURAZIONE ROBOT (Lettura 03E9) ---
    def _refresh_robot_configuration(self):
        """Scansiona il JSON per trovare Ruote e Sfere collegate."""
        if not self._structure_json: return
        
        self.robot_wheels = []
        self.robot_joints = []
        self.robot_distance = []
        
        # Pulisce le configurazioni precedenti per evitare ID fantasma
        current_ids = set()

        for node in self._structure_json.get("STRUCTURE", []):
            try:
                m_index = int(node.get("mIndex", -1))
                m_type = int(node.get("type", 0))
                
                if m_index <= 0: continue
                current_ids.add(m_index)
                
                if m_type == 3: # Ruota
                    self.robot_wheels.append(m_index)
                elif m_type == 1: # Sfera (Joint)
                    self.robot_joints.append(m_index)
                elif m_type == 4:      # Sensore distanza
                    self.robot_distance.append(m_index)
            except Exception: pass
        
        # ORDINA LE LISTE (Cruciale per coerenza)
        self.robot_wheels.sort()
        self.robot_joints.sort()
        self.robot_distance.sort()
        self._log(f"[CONF] Sensori distanza: {self.robot_distance}\n")
        # Rimuove ruote configurate manualmente se non esistono più fisicamente
        self.wheels_left = [w for w in self.wheels_left if w in self.robot_wheels]
        self.wheels_right = [w for w in self.wheels_right if w in self.robot_wheels]
                
        self._log(f"[CONF] Trovate {len(self.robot_wheels)} ruote e {len(self.robot_joints)} sfere.\n")
        
        # Auto-assegnazione ruote se liste vuote (Euristica: dispari=SX, pari=DX)
        if not self.wheels_left and not self.wheels_right and self.robot_wheels:
            for w in self.robot_wheels:
                if w % 2 != 0: self.wheels_left.append(w)
                else: self.wheels_right.append(w)
            self.wheels_left.sort()
            self.wheels_right.sort()
            self._log(f"[CONF] Auto-assegnate SX:{self.wheels_left} DX:{self.wheels_right}\n")
            self.wheels_manual_config = False

    # --- LOGICA DRIVE MODE (NUOVA) ---
    def _toggle_drive_mode(self):
        if not self.sock: return
        
        # Incrementa contatore comandi
        cmd_id = self._cmd_counter_std
        self._cmd_counter_std = (self._cmd_counter_std + 1) & 0xFFFF
        
        if self._drive_mode_active:
            # Stiamo spegnendo -> Inviamo 0x02
            payload = b"\x02"
            note = "Stop Drive (0x02)"
            new_state = False
        else:
            # Stiamo accendendo -> Inviamo 0x03
            payload = b"\x03"
            note = "Start Drive (0x03)"
            new_state = True
            
        # Costruisci pacchetto: Type 0x0064
        # Struct: Type(H), Cmd(H), Len(I) + Payload
        header = struct.pack("<HHI", 0x0064, cmd_id, 1)
        self._tx(header + payload, note=f"STD 0064/{cmd_id:04X} {note}")
        
        self._drive_mode_active = new_state
        self._update_drive_btn_ui()

    def _update_drive_btn_ui(self):
        try:
            if self._drive_mode_active:
                self.lbl_drive_status.config(text="MODALITÀ GUIDA: ATTIVA", foreground="green")
                self.btn_drive_toggle.config(text="DISATTIVA (0x02)")
            else:
                self.lbl_drive_status.config(text="MODALITÀ GUIDA: SPENTA", foreground="red")
                self.btn_drive_toggle.config(text="ATTIVA GUIDA (0x03)")
        except Exception: pass

    # --- Logica di Programmazione (Snapshot con WIZARD) ---
    def _program_dir(self, direction):
        # Apre la finestra Wizard invece di eseguire comandi diretti
        ProgrammingWizard(self, direction, self)

    def save_snapshot_for_direction(self, direction):
        # Chiamato dal Wizard alla fine
        snapshot = {}
        for j in self.robot_joints:
            node = self._structure_by_index.get(j)
            if node:
                snapshot[j] = float(node.get("angle", 0.0))
        
        self.poses[direction] = snapshot
        self._log(f"[PROG] Salvata posa {direction} ({len(snapshot)} giunti).\n")


    def _save_wheel_sample_for_direction(self, direction, sample):
        """Salva una snapshot ruote (03F3) e tenta auto-config (inverti + SX/DX)."""
        try:
            direction = str(direction).upper()
        except Exception:
            return
        if not hasattr(self, "_wizard_wheel_samples"):
            self._wizard_wheel_samples = {}
        try:
            clean = {int(mid): int(val) for mid, val in dict(sample).items() if int(mid) in self.robot_wheels}
        except Exception:
            return
        if not clean:
            return
        self._wizard_wheel_samples[direction] = clean
        self._log(f"[AUTO] 03F3 salvato per {direction}: {clean}\n")
        self._auto_configure_wheels_from_samples()

    def _auto_configure_wheels_from_samples(self):
        """Auto-config su base 03F3:
        - Polarità (inverti ruote che in UP vanno in segno -)
        - Separazione ruote SX/DX usando LEFT + RIGHT (spin o differenziale)
        """
        if not self.robot_wheels:
            return
        samples = getattr(self, "_wizard_wheel_samples", {}) or {}

        # -------------------------
        # 1) POLARITÀ da UP
        # -------------------------
        up = samples.get("UP") or {}
        if up:
            changed = False
            for mid, raw in up.items():
                if abs(int(raw)) < 5:
                    continue
                pol = 1 if int(raw) >= 0 else -1
                if self.wheel_polarity.get(mid) != pol:
                    self.wheel_polarity[mid] = pol
                    changed = True
            if changed:
                inv = sorted([m for m in self.robot_wheels if self.wheel_polarity.get(m, 1) == -1])
                self._log(f"[AUTO] Polarity ruote aggiornata. Invertite: {inv}\n")

        # -------------------------
        # 2) SX/DX da LEFT + RIGHT
        # -------------------------
        left = samples.get("LEFT") or {}
        right = samples.get("RIGHT") or {}
        if not left or not right:
            return

        # Non sovrascrivere se l'utente ha configurato manualmente (ma se è vuoto, sì)
        if getattr(self, "wheels_manual_config", False) and (self.wheels_left or self.wheels_right):
            self._log("[AUTO] Ruote SX/DX non aggiornate: configurazione manuale attiva.\n")
            return

        mids = sorted(set(left.keys()) & set(right.keys()) & set(self.robot_wheels))
        if len(mids) < 2:
            return

        def _pol(mid):
            return int(self.wheel_polarity.get(mid, 1))

        # Applica polarità: valori >0 significano 'avanti' coerente con UP
        cl = {m: int(left[m]) * _pol(m) for m in mids}
        cr = {m: int(right[m]) * _pol(m) for m in mids}

        def sgn(v):
            return 1 if v > 0 else (-1 if v < 0 else 0)

        cand_r = set()
        cand_l = set()

        # Caso A: "spin" (segni opposti fra LEFT/RIGHT)
        for m in mids:
            sl, sr = sgn(cl[m]), sgn(cr[m])
            # Se quando giro a sinistra m va avanti e quando giro a destra va indietro -> RUOTA DESTRA
            if sl == 1 and sr == -1:
                cand_r.add(m)
            # Viceversa -> RUOTA SINISTRA
            elif sl == -1 and sr == 1:
                cand_l.add(m)

        # Caso B: "differenziale" (tutte avanti, ma con intensità diversa)
        if len(cand_l) + len(cand_r) < 2:
            for m in mids:
                dl = abs(cl[m]) - abs(cr[m])
                if dl > 2:
                    cand_r.add(m)
                elif dl < -2:
                    cand_l.add(m)

        if not cand_l and not cand_r:
            return

        # Assicura almeno una ruota per lato
        if not cand_l:
            m = sorted(cand_r)[0]
            cand_r.remove(m)
            cand_l.add(m)
        if not cand_r:
            m = sorted(cand_l)[0]
            cand_l.remove(m)
            cand_r.add(m)

        # Bilanciamento (se 4 ruote, tipicamente 2/2)
        target = max(1, len(mids) // 2)

        remaining = [m for m in mids if m not in cand_l and m not in cand_r]
        for m in remaining:
            dl = abs(cl[m]) - abs(cr[m])
            if len(cand_r) < target and dl >= 0:
                cand_r.add(m)
            elif len(cand_l) < target and dl < 0:
                cand_l.add(m)
            else:
                (cand_l if len(cand_l) < len(cand_r) else cand_r).add(m)

        self.wheels_left = sorted(list(cand_l))
        self.wheels_right = sorted(list(cand_r))
        self._log(f"[AUTO] Assegnazione ruote aggiornata da 03F3. SX:{self.wheels_left} DX:{self.wheels_right}\n")

    # --- Utility Helpers per il Wizard ---

    # --- JSON DIREZIONI (actType=2 / volante) ---
    def _build_drive_posture(self, pose: dict, wheel_sample: dict):
        """Costruisce una lista POSTURE (giunti + ruote) per una direzione.
        - pose: {joint_id: angle}
        - wheel_sample: {wheel_id: signed_val} (da 03F3)
        """
        pose = pose or {}
        wheel_sample = wheel_sample or {}

        # 1) Giunti
        posture = []
        for mid in sorted(pose.keys()):
            try:
                posture.append({
                    "angle": float(pose[mid]),
                    "forward": False,
                    "inTangent": 0.0,
                    "inWeight": 0.0,
                    "moduleId": int(mid),
                    "moduleRotateForward": False,
                    "outTangent": 0.0,
                    "outWeight": 0.0,
                    "rotate": False,
                    "speed": 70,
                    "type": 1
                })
            except Exception:
                continue

        # 2) Ruote (normalizzate 0..100 rispetto al max_abs della direzione)
        raw = {}
        for mid, val in dict(wheel_sample).items():
            try:
                mid = int(mid)
                if mid in self.robot_wheels:
                    raw[mid] = int(val)
            except Exception:
                pass

        if raw:
            max_abs = max([abs(v) for v in raw.values()] + [1])
            for mid in sorted(raw.keys()):
                val = raw[mid]
                sp = int(round(abs(val) * 100.0 / max_abs))
                sp = max(0, min(100, sp))
                posture.append({
                    "angle": 0.0,
                    "forward": bool(val >= 0),
                    "inTangent": 0.0,
                    "inWeight": 0.0,
                    "moduleId": int(mid),
                    "moduleRotateForward": False,
                    "outTangent": 0.0,
                    "outWeight": 0.0,
                    "rotate": True,
                    "speed": int(sp),
                    "type": 3
                })

        posture.sort(key=lambda x: int(x.get("moduleId", 0)))
        return posture

    def build_drive_action_json_from_data(self, poses: dict, samples: dict, act_name="steering", act_index=0):
        """Crea un'azione volante completa (actType=2) da poses/samples.
        poses: {"UP":{...}, "LEFT":{...}, "RIGHT":{...}}
        samples: {"UP":{wheel:signed}, "LEFT":{...}, "RIGHT":{...}}
        """
        poses = poses or {}
        samples = samples or {}

        for d in ("UP", "LEFT", "RIGHT"):
            if not poses.get(d):
                raise RuntimeError(f"Manca la posa '{d}'.")
            if not samples.get(d):
                raise RuntimeError(f"Manca 03F3 per '{d}'.")

        def _step(step_idx, pose_dir, wheel_dir):
            return {
                "POSTURE": self._build_drive_posture(poses.get(pose_dir), samples.get(wheel_dir)),
                "delayTime": 0.0,
                "executeTime": 0.0,
                "groupNumber": 0,
                "isGroupNode": 0,
                "minExecuteTime": 0.0,
                "segmentIndex": 0,
                "startTime": 0.0,
                "steeringIndex": -1,
                "stepIndex": int(step_idx)
            }

        steps = [
            _step(1, "UP", "UP"),
            _step(2, "UP", "UP"),
            _step(3, "RIGHT", "RIGHT"),
            _step(4, "LEFT", "LEFT"),
        ]

        return {
            "STEP": steps,
            "actIndex": int(act_index),
            "actName": str(act_name),
            "actType": 2,
            "isSelect": False,
            "model_id": 0
        }

    def build_drive_action_json(self, act_name="steering"):
        """Compatibilità: genera actType=2 usando self.poses + _wizard_wheel_samples."""
        needed = ["UP", "LEFT", "RIGHT"]
        poses = {}
        samples = {}
        for d in needed:
            if not self.poses.get(d):
                raise RuntimeError(f"Manca la posa '{d}'. Programma prima SU/SX/DX.")
            poses[d] = dict(self.poses.get(d))

        ws = getattr(self, "_wizard_wheel_samples", {}) or {}
        for d in needed:
            if not ws.get(d):
                raise RuntimeError(f"Manca 03F3 per '{d}'. Apri la programmazione '{d}' e muovi il robot quando richiesto.")
            samples[d] = dict(ws.get(d))

        return self.build_drive_action_json_from_data(poses=poses, samples=samples, act_name=act_name, act_index=0)


    def get_all_module_ids(self):
        # Ritorna la lista di tutti gli ID trovati nella struttura
        ids = []
        if self._structure_json:
            for n in self._structure_json.get("STRUCTURE", []):
                try: 
                    mi = int(n.get("mIndex", 0))
                    if mi > 0: ids.append(mi)
                except: pass
        return sorted(list(set(ids)))

       # --- XBOX CONTROLLER LOGIC (NUOVO) ---
    # --- LOGICA XBOX (XINPUT NATIVO) ---

    def _monitor_xbox(self):
        self._log("[XBOX] Monitoraggio Full-Input avviato...\n")
        
        if XInput:
            try:
                XInput.set_deadzone(XInput.DEADZONE_LEFT_THUMB, 5000) 
                XInput.set_deadzone(XInput.DEADZONE_RIGHT_THUMB, 5000) 
            except: pass

        while self.xbox_running:
            if not XInput: break
            
            # Trova primo controller connesso
            connected = XInput.get_connected()
            idx = -1
            for i in range(4):
                if connected[i]:
                    idx = i
                    break
            
            if idx != -1:
                try:
                    state = XInput.get_state(idx)
                    
                    # 1. Lettura Valori Grezzi
                    lt, rt = XInput.get_trigger_values(state)
                    thumbs = XInput.get_thumb_values(state)
                    buttons = XInput.get_button_values(state) # Restituisce dict {'A': bool, ...}
                    
                    lx, ly = thumbs[0][0], thumbs[0][1]
                    rx, ry = thumbs[1][0], thumbs[1][1]
                    
                    # 2. Processo Guida Standard (Drive Mode) - Vecchio Metodo
                    # (Mantiene la logica auto esistente su LX/Triggers)
                    self._process_xbox_input(lx, ly)
                    
                    # 3. Processo Mappatura Custom - NUOVO Metodo
                    # Costruisco mappa completa degli input attuali
                    full_map = {
                        # Assi
                        "AXIS_LX": lx, "AXIS_LY": ly,
                        "AXIS_RX": rx, "AXIS_RY": ry,
                        "TRIG_L": lt,  "TRIG_R": rt,
                        
                        # Bottoni Base
                        "BTN_A": buttons.get("A"), "BTN_B": buttons.get("B"),
                        "BTN_X": buttons.get("X"), "BTN_Y": buttons.get("Y"),
                        
                        # DPAD
                        "PAD_UP": buttons.get("DPAD_UP"), "PAD_DOWN": buttons.get("DPAD_DOWN"),
                        "PAD_LEFT": buttons.get("DPAD_LEFT"), "PAD_RIGHT": buttons.get("DPAD_RIGHT"),
                        
                        # [NUOVI] Spalle
                        "BTN_LB": buttons.get("LEFT_SHOULDER"), 
                        "BTN_RB": buttons.get("RIGHT_SHOULDER"),
                        
                        # [NUOVI] Centro
                        "BTN_START": buttons.get("START"),
                        "BTN_BACK": buttons.get("BACK"),
                        
                        # [NUOVI] Stick Clicks
                        "BTN_THUMB_L": buttons.get("LEFT_THUMB"),
                        "BTN_THUMB_R": buttons.get("RIGHT_THUMB")
                    }
                    self._process_mapped_input(full_map)
                    
                except Exception: pass
            else:
                time.sleep(1.0)
            
            time.sleep(0.02) # ~50Hz (Importante per fluidità servo)

    def _process_xbox_input(self, val_x, val_y):
        # Stick SX:
        # val_x: -1.0 (SX) a 1.0 (DX)
        # val_y: -1.0 (Giù/Retro) a 1.0 (Su/Avanti)
        
        # Deadzone extra software
        if abs(val_x) < 0.05: val_x = 0
        if abs(val_y) < 0.05: val_y = 0
        
        nx = val_x
        ny = val_y
        
        # Safety Reverse (Se vado avanti e tiro indietro di colpo)
        if self.last_xbox_y > 0.1 and ny < -0.1:
            if self.udp_mode.get(): self._send_udp_drive(nx, 0)
            else: self._send_hex_drive(nx, 0) 
            
            time.sleep(0.15)
            self.last_xbox_y = 0 
            return

        self.last_xbox_y = ny
        self.after(0, lambda: self._sync_xbox_to_ui(nx, ny))

    def _sync_xbox_to_ui(self, nx, ny):
        if not self.poses.get("UP") and not self.poses.get("RIGHT") and not self.poses.get("LEFT"):
            return
        
        nx = max(-1.0, min(1.0, nx))
        ny = max(-1.0, min(1.0, ny))
        
        # Se 0,0 gestisci lo stop/lock
        if nx == 0 and ny == 0:
            if self.last_sent_joy_data != (0.0, 0.0):
                self.last_sent_joy_data = (0.0, 0.0)
                if self.udp_mode.get(): self._send_udp_drive(0, 0)
                elif self._drive_mode_active:
                    time.sleep(0.02)
                    self._on_lock_all_pressed(1)
            return

        if self.udp_mode.get() or self._drive_mode_active:
            if time.time() - self.last_joy_time < 0.05: return
            lx, ly = self.last_sent_joy_data
            if abs(nx - lx) < 0.02 and abs(ny - ly) < 0.02: return
            self.last_joy_time = time.time()
            self.last_sent_joy_data = (nx, ny)
            if self.udp_mode.get(): self._send_udp_drive(nx, ny)
            else: self._send_hex_drive(nx, ny)

    def _on_joy_move(self, e, cv, ball):
        w, h = 300, 300
        nx = (e.x - 150) / 100.0
        ny = -(e.y - 150) / 100.0
        if abs(nx) < 0.05: nx = 0
        if abs(ny) < 0.05: ny = 0
        nx, ny = max(-1, min(1, nx)), max(-1, min(1, ny))
        cv.coords(ball, e.x-15, e.y-15, e.x+15, e.y+15)
        
        if not self.udp_mode.get() and not self._drive_mode_active: return
        if time.time() - self.last_joy_time < 0.08: return
        
        lx, ly = self.last_sent_joy_data
        if nx==0 and ny==0 and lx==0 and ly==0: return
        if abs(nx-lx) < 0.02 and abs(ny-ly) < 0.02: return
        
        self.last_joy_time = time.time()
        self.last_sent_joy_data = (nx, ny)
        if self.udp_mode.get(): self._send_udp_drive(nx, ny)
        else: self._send_hex_drive(nx, ny)

    def _on_joy_release(self, e, cv, ball):
        cv.coords(ball, 135, 135, 165, 165)
        self.last_sent_joy_data = (0.0, 0.0)
        if self.udp_mode.get(): 
            self._send_udp_drive(0, 0)
        elif self._drive_mode_active:
            time.sleep(0.02)
            self._on_lock_all_pressed(1)
             
    def calculate_curvature_drive(self, throttle, turn, speed_mult,
                                  min_inner=0.35,   # <-- NON scendere troppo: 0.25–0.45 tipico
                                  turn_expo=1.2,    # più dolce vicino al centro
                                  deadzone=0.05):

        throttle = float(throttle)
        turn = float(turn)

        # se non stai dando gas, fermo (no pivot)
        if abs(throttle) < deadzone:
            return 0.0, 0.0

        # clamp ingressi
        throttle = max(-1.0, min(1.0, throttle))
        turn = max(-1.0, min(1.0, turn))

        # expo sullo sterzo
        s = 1.0 if turn >= 0 else -1.0
        turn = s * (abs(turn) ** float(turn_expo))

        # curva con minimo interno:
        # k va da 1.0 (dritto) a min_inner (sterzo massimo)
        k = 1.0 - abs(turn) * (1.0 - float(min_inner))
        inner = throttle * k
        outer = throttle

        # turn > 0 = destra -> destra è interna
        if turn >= 0:
            left, right = outer, inner
        else:
            left, right = inner, outer

        return left * speed_mult, right * speed_mult


    # --- NUOVA LOGICA: UDP DRIVE (CORRETTA POLARITÀ) ---
    def _send_udp_drive(self, x, y):
        """Invia comandi via UDP allo script drive_server.py sul robot."""
        # 1. Calcolo Velocità (Range 0-1000 per lo script Python)
        # Scala lo slider (1-100) al range dello script
        spd_scale = (self.speed_var.get() / 100.0) * 1000.0
        
        # Calcolo Curvature Drive (Arcade migliorato)
        vl, vr = self.calculate_curvature_drive(y, x, spd_scale)
        vl = int(vl)
        vr = int(vr)
        
        parts = []
        
        # Ruote SX
        for mid in self.wheels_left: 
            pol = self.wheel_polarity.get(mid, 1)
            parts.append(f"{mid}:w:{int(vl * pol)}")
            
        # Ruote DX
        for mid in self.wheels_right: 
            pol = self.wheel_polarity.get(mid, 1)
            parts.append(f"{mid}:w:{int(vr * pol)}")
        
        # 2. Calcolo Sfere (Joints)
        # (Logica identica per HEX e UDP per coerenza di movimento)
        rest = self.poses.get("REST", {})
        # Fallback se non calibrato
        if not rest and self.robot_joints: 
             rest = {j: self._structure_by_index[j].get("angle", 0) for j in self.robot_joints}
        
        w_up = max(0.0, y)
        w_right = max(0.0, x)
        w_left = max(0.0, -x)
        
        # Helper per evitare rotazioni di 360° (Shortest Path)
        def ang_diff(a, b):
            d = a - b
            while d > 180: d -= 360
            while d <= -180: d += 360
            return d

        for j in self.robot_joints:
            base_ang = rest.get(j, 0.0)
            t_up = self.poses.get("UP", {}).get(j, base_ang)
            t_r = self.poses.get("RIGHT", {}).get(j, base_ang)
            t_l = self.poses.get("LEFT", {}).get(j, base_ang)
            
            # Mixing vettoriale
            final_ang = base_ang + \
                        (ang_diff(t_up, base_ang) * w_up) + \
                        (ang_diff(t_r, base_ang) * w_right) + \
                        (ang_diff(t_l, base_ang) * w_left)
            
            # UDP accetta gradi diretti
            parts.append(f"{j}:j:{int(final_ang)}")
            
        # Invio stringa unica
        msg = ",".join(parts).encode('utf-8')
        try: self.udp_sock.sendto(msg, (self.ip_var.get(), 20002))
        except: pass

    def _send_hex_drive(self, x, y):
        """Costruisce e invia il pacchetto 0x03F4 (Protocollo Nativo)."""
        # 1. Calcolo Velocità (Range 0-255 per il protocollo HEX)
        # Scala lo slider (1-100) al byte range
        spd_scale = (self.speed_var.get() / 100.0) * 255.0
        
        vl, vr = self.calculate_curvature_drive(y, x, spd_scale)
        
        # Clamp a +/- 255
        vl = int(max(-255, min(255, vl)))
        vr = int(max(-255, min(255, vr)))
        
        wheel_cmds = []
        
        # Helper locale: converte velocità con segno nel formato [DIR][SPEED]
        def get_wheel_bytes(mid, signed_speed):
            pol = self.wheel_polarity.get(mid, 1) # Default 1
            final = signed_speed * pol
            
            # Protocollo Keyi: 
            # 0x01 = Negativo (CCW/Indietro)
            # 0x00 = Positivo (CW/Avanti)
            spd = int(abs(final))
            if spd > 255: spd = 255
            if final < 0: return (mid, 0x01, spd)
            else: return (mid, 0x00, spd)

        # Assegnazione SX/DX
        if self.wheels_left or self.wheels_right:
            for w in self.wheels_left: wheel_cmds.append(get_wheel_bytes(w, vl))
            for w in self.wheels_right: wheel_cmds.append(get_wheel_bytes(w, vr))
        else:
            # Fallback (tutte le ruote vanno con Y)
            raw_spd = int(y * spd_scale)
            for w in self.robot_wheels: wheel_cmds.append(get_wheel_bytes(w, raw_spd))
            
        # ORDINAMENTO PER ID (CRUCIALE PER IL FIRMWARE)
        wheel_cmds.sort(key=lambda item: item[0])
        
        # Costruzione Payload Ruote
        w_data = bytearray()
        for mid, d_byte, s_byte in wheel_cmds:
            w_data.append(mid)
            w_data.append(d_byte) # Direzione
            w_data.append(s_byte) # Velocità

        # 2. Calcolo Sfere (Joints) - Identico alla logica UDP ma impacchettato
        rest = self.poses.get("REST", {})
        if not rest and self.robot_joints: 
             rest = {j: self._structure_by_index[j].get("angle", 0) for j in self.robot_joints}

        w_up = max(0.0, y)
        w_right = max(0.0, x)
        w_left = max(0.0, -x)
        
        def ang_diff(a, b):
            d = a - b
            while d > 180: d -= 360
            while d <= -180: d += 360
            return d
            
        j_data = bytearray()
        for j in self.robot_joints:
            base = rest.get(j, 0.0)
            t_up = self.poses.get("UP", {}).get(j, base)
            t_r = self.poses.get("RIGHT", {}).get(j, base)
            t_l = self.poses.get("LEFT", {}).get(j, base)
            
            final = base + (ang_diff(t_up, base) * w_up) + \
                           (ang_diff(t_r, base) * w_right) + \
                           (ang_diff(t_l, base) * w_left)
            final = final % 360.0
            
            # Conversione in RAW (0-4096) Little Endian
            raw = int(final / ANGLE_SCALE)
            j_data.append(j)
            j_data.extend(bytes.fromhex("024600")) # Magic bytes
            j_data.extend(struct.pack("<H", raw & 0xFFFF))

        # Assemblaggio Pacchetto Completo: [LenW][DataW] [LenJ][DataJ]
        pl = struct.pack("<I", len(w_data)) + w_data + struct.pack("<I", len(j_data)) + j_data
        
        self._tx(pack_std(0x03F4, self._cmd_counter_std, pl))
        self._cmd_counter_std = (self._cmd_counter_std + 1) & 0xFFFF

    def _on_lock_all_pressed(self, locked):
        ids = self.get_all_module_ids()
        if not ids: return
        pl = bytearray()
        for i in ids: pl.extend([i, 1 if locked else 0])
        self._tx(pack_std(0x03F8, self._cmd_counter_std, pl))
        self._cmd_counter_std = (self._cmd_counter_std + 1) & 0xFFFF

    # ---------- LOG ----------
    def _log(self, s: str):
        self.log_q.put(s)

    def _drain_log_queue(self):
        try:
            while True:
                s = self.log_q.get_nowait()
                self.log.insert("end", s)
                self.log.see("end")
        except queue.Empty:
            pass
        self.after(50, self._drain_log_queue)

    # ---------- TX helper ----------
    def _tx(self, data: bytes, note=""):
        if not self.sock:
            return
        with self.sock_lock:
            self.sock.sendall(data)
        if note:
            self._log(f"TX {len(data)} bytes {note}\n")
    
    def _next_cmd(self):
        """Genera il prossimo ID comando incrementale."""
        # Se per caso la variabile non è inizializzata, usa 0
        c = getattr(self, "_cmd_counter_std", 0)
        self._cmd_counter_std = (c + 1) & 0xFFFF
        return c

    # ---------- CONNECT / DISCONNECT ----------
    def connect_and_handshake(self):
        if self.sock:
            messagebox.showinfo("Info", "Già connesso.")
            return
        ip = self.ip_var.get().strip()
        port = int(self.port_var.get())
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ip, port))
            s.settimeout(0.5)
        except Exception as e:
            messagebox.showerror("Errore", f"Connessione fallita: {e}")
            return

        self.sock = s
        self.running = True
        self.rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self.rx_thread.start()
        self.keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self.keepalive_thread.start()
        self.btn_disconnect.config(state="normal")
        self.btn_connect.config(state="disabled")
        self.btn_upload.config(state="normal")
        self.btn_play_zip.config(state="normal")
        self.btn_stop_zip.config(state="normal")
        self.btn_assembly.config(state="normal")
        self.btn_ping.config(state="normal")
        self.btn_handshake.config(state="normal")
        self._log(f"[+] Connesso a {ip}:{port}\n")
        self._do_handshake()

    def disconnect(self):
        self.running = False
        s = self.sock
        self.sock = None
        if s:
            try: s.close()
            except Exception: pass
        self._assembly_active = False
        try: self._refresh_json_controls()
        except Exception: pass
        self.btn_disconnect.config(state="disabled")
        self.btn_connect.config(state="normal")
        self.btn_upload.config(state="disabled")
        self.btn_play_zip.config(state="disabled")
        self.btn_stop_zip.config(state="disabled")
        self.btn_assembly.config(state="disabled")
        self.btn_exit_assembly.config(state="disabled")
        self.btn_ping.config(state="disabled")
        self.btn_handshake.config(state="disabled")
        try: self.btn_modules.config(state="disabled")
        except Exception: pass

    # ---------- KEEPALIVE ----------
    def _keepalive_loop(self):
        while self.running and self.sock:
            if self.keepalive_pause.is_set():
                time.sleep(0.05)
                continue
            try: self._tx(HELLO8, note="HELLO8 (keepalive)")
            except Exception: break
            ms = int(self.keepalive_ms.get())
            if ms < 100: ms = 100
            time.sleep(ms / 1000.0)

    # ---------- RX loop (parse frames) ----------
    def _rx_loop(self):
        buf = b""
        try:
            while self.running and self.sock:
                try: data = self.sock.recv(4096)
                except socket.timeout: continue
                except Exception: break
                if not data: break
                if data == HELLO8:
                    try: self._tx(HELLO8, note="HELLO8 (pong)")
                    except Exception: pass
                    continue
                buf += data
                while True:
                    if len(buf) < 8: break
                    msg_type, cmd, ln = unpack_header8(buf[:8])
                    if ln > 1024 * 1024:
                        self._log(f"RX {len(buf)} bytes (blob)\n")
                        js = try_extract_json(buf)
                        if js is not None: self._log(f"    ↳ JSON/Str: {js}\n")
                        buf = b""
                        break
                    if len(buf) < 8 + ln: break
                    payload = buf[8:8 + ln]
                    buf = buf[8 + ln:]
                    self._on_frame(msg_type, cmd, payload)
        finally:
            self._log("[*] Connessione chiusa dal peer.\n")
            self.disconnect()

    def _on_frame(self, msg_type, cmd, payload):
        ln = len(payload)
        self._log(f"RX 0x{msg_type:04X} cmd=0x{cmd:04X} len={ln}\n")
        
        # Rilevamento Movimento (Wizard)
        if msg_type == 0x03F3:
            if self.active_wizard:
                data = parse_03f3_payload(payload)
                self.active_wizard.on_f3_received(data)
            else:
                self._log("[!!!] Rilevato movimento 03F3 (No wizard active)\n")

        # Parsing Struttura e Aggiornamenti
        if msg_type in (0x03E9, 0x03EB):
            try:
                # 1. Parsing Struttura (03E9)
                if msg_type == 0x03E9:
                    obj = parse_03e9_payload_to_structure(payload)
                    self._structure_json = obj
                    self._structure_by_index = {int(n['mIndex']): n for n in obj['STRUCTURE']}
                    
                    # --- FIX: Aggiorna la variabile di testo per la finestra "Mostra JSON" ---
                    self._last_structure_json_text = json.dumps(obj, indent=2)
                    
                    # Aggiorna UI e Configurazione interna
                    self.after(0, lambda: [self._refresh_json_controls(), self._refresh_robot_configuration()])
                    
                    # Pubblica su WS se attivo
                    if self.ws_enabled: 
                        self.ws_bridge.publish(json.dumps(obj))
                
                # 2. Parsing Aggiornamenti Angoli (03EB)
                elif msg_type == 0x03EB:
                    if self._structure_json and self._structure_by_index:
                        updates = parse_03eb_payload_to_updates(payload)
                        for mi, _, deg in updates:
                            node = self._structure_by_index.get(mi)
                            if node is not None: node["angle"] = deg
                        
                        # --- FIX: Aggiorna anche il testo live con i nuovi angoli ---
                        self._last_structure_json_text = json.dumps(self._structure_json, indent=2)

                        # Pubblica su WS se attivo
                        if self.ws_enabled:
                            self.ws_bridge.publish(json.dumps(self._structure_json))
            except Exception as e:
                # self._log(f"[ERR] Parsing frame: {e}\n") 
                pass

        # Log generico per altri pacchetti (o debug struttura)
        if msg_type == 0x03E9:
            n = ln // 0x1C if ln % 0x1C == 0 else None
            if n is not None: self._log(f"    ↳ MODULE STRUCT: {n} moduli (len=0x{ln:X})\n")
            # self._log(f"    payload(hex) {hexdump(payload, 512)}\n") # Ridotto spam
        elif msg_type == 0x03EB:
            self._log(f"    ↳ MODULE LIVE (03EB) payload(hex) {hexdump(payload, 64)}\n")
        else:
            # Tenta di decodificare stringhe JSON per altri comandi
            js = try_extract_json(payload)
            if js is not None: self._log(f"    ↳ JSON/Str: {js}\n")
            else: self._log(f"    payload(hex) {hexdump(payload, 256)}\n")

    # ---------- HANDSHAKE ----------
    def _do_handshake(self):
        if not self.sock: return
        token = self.token_var.get().strip()
        payload_obj = {
            "appVersion": "2.6.17", "blocklyVersion": "1.7.4", "brainAppVersion": "1.0",
            "deviceName": self.devname_var.get().strip() or "PC-Python",
            "deviceToken": token if token else "PYTHON_TOKEN", "invite": 1,
            "jsonType": 1, "platform": "Android", "reconnect": 0, "userId": 1,
            "userName": self.username_var.get().strip() or "PythonClient"
        }
        json_bytes = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
        try:
            self.keepalive_pause.set()
            self._tx(HELLO8, note="HELLO8")
            time.sleep(0.05)
            f1 = pack_std(0x0009, 0x0002, json_bytes)
            self._tx(f1, note=f"STD 0009/0002 (JSON hello) len={len(json_bytes)}")
            time.sleep(0.05)
            f2 = pack_std(0x0064, 0x0003, b"\x00")
            self._tx(f2, note="STD 0064/0003 payload=00")
            time.sleep(0.05)
            f3 = pack_std(0x0067, 0x0004, b"\x02\x00")
            self._tx(f3, note="STD 0067/0004 payload=0200")
            time.sleep(0.05)
            self._tx(HELLO8, note="HELLO8 (again)")
            self._log("[*] Handshake inviato.\n")
        except Exception as e:
            self._log(f"[!] Errore handshake: {e}\n")
        finally:
            self.keepalive_pause.clear()

    # ---------- MODULI / ASSEMBLY ----------
    def send_ping(self):
        if not self.sock: return
        try: self._tx(pack_mini(0x03E3, 0x0000), note="MINI 03E3 (ping)")
        except Exception as e: self._log(f"[!] Errore ping: {e}\n")

    def enter_assembly_mode(self):
        if not self.sock:
            messagebox.showwarning("Info", "Non sei connesso.")
            return
        try:
            self.keepalive_pause.set()
            # Sequenza di INGRESSO (già presente nel tuo codice)
            seq = [
                (pack_mini(0x03E3, 0x0000), "MINI 03E3/0000"),
                (pack_std(0x0067, 0x000C, b"\x01\x00"), "STD 0067/000C payload=0100"),
                (pack_std(0x03FC, 0x000D, b"\x00\x00"), "STD 03FC/000D payload=0000"),
                (pack_mini(0x03E8, 0x000E), "MINI 03E8/000E"),
                (pack_std(0x0064, 0x000F, b"\x01"), "STD 0064/000F payload=01"),
                (pack_std(0x0068, 0x0000, b"\x01\x00"), "STD 0068/0000 payload=0100"),
            ]
            for data, note in seq:
                self._tx(data, note=note)
                time.sleep(0.05)
            
            self._assembly_active = True
            
            # Gestione stato pulsanti
            self.btn_assembly.config(state="disabled")
            self.btn_exit_assembly.config(state="normal")
            
            try: self.after(0, self._refresh_json_controls)
            except Exception: pass
            self._log("[*] Modalità ASSEMBLAGGIO attivata (Attesa 03E9...).\n")
        except Exception as e:
            self._log(f"[!] Errore enter_assembly_mode: {e}\n")
        finally:
            self.keepalive_pause.clear()

    def exit_assembly_mode(self):
        if not self.sock: return
        try:
            self.keepalive_pause.set()
            # Sequenza di USCITA decodificata dai tuoi log
            seq = [
                # 6700 0900 02000000 0200
                (pack_std(0x0067, 0x0009, b"\x02\x00"), "STD 0067/0009 payload=0200"),
                # 6400 0a00 01000000 00
                (pack_std(0x0064, 0x000A, b"\x00"),"STD 0064/000A payload=00"),
                # 6700 0b00 02000000 0200
                (pack_std(0x0067, 0x000B, b"\x02\x00"), "STD 0067/000B payload=0200"),
                # e303... (Ping)
                (pack_mini(0x03E3, 0x0000),"MINI 03E3 (ping)"),
                # 6800 0000 02000000 0100
                (pack_std(0x0068, 0x0000, b"\x01\x00"), "STD 0068/0000 payload=0100")
            ]
            
            for data, note in seq:
                self._tx(data, note=note)
                time.sleep(0.05)
                
            self._assembly_active = False
            
            # Gestione stato pulsanti
            self.btn_assembly.config(state="normal")
            self.btn_exit_assembly.config(state="disabled")
            
            try: self.after(0, self._refresh_json_controls)
            except Exception: pass
            self._log("[*] Uscita modalità ASSEMBLAGGIO effettuata.\n")
        except Exception as e:
            self._log(f"[!] Errore exit_assembly_mode: {e}\n")
        finally:
            self.keepalive_pause.clear()

    # ---------- FILE PICK ----------
    def pick_zip(self):
        p = filedialog.askopenfilename(title="Scegli file ZIP", filetypes=[("ZIP", "*.zip"), ("All files", "*.*")])
        if p: self.zip_path.set(p)

    # ---------- UPLOAD ZIP ----------
    def upload_zip_sniff(self):
        if not self.sock:
            messagebox.showwarning("Info", "Non sei connesso.")
            return
        p = self.zip_path.get().strip()
        if not p:
            messagebox.showwarning("Info", "Scegli prima uno ZIP.")
            return
        try:
            with open(p, "rb") as f: zip_bytes = f.read()
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile leggere ZIP: {e}")
            return
        try: map_number = json.loads(self.mapnum_var.get().strip())
        except Exception: map_number = {"0": 0, "1": 1}
        try: map_angle = json.loads(self.mapang_var.get().strip())
        except Exception: map_angle = {"0": 0, "1": 0}
        meta_obj = {"fileName": rand_zip_name(), "mapNumber": map_number, "mapAngle": map_angle, "fileType": int(self.filetype_var.get())}
        meta_json = json.dumps(meta_obj, separators=(",", ":")).encode("utf-8")
        json_len = len(meta_json)
        zip_len = len(zip_bytes)
        total_len = 4 + json_len + 4 + zip_len
        header = struct.pack("<HHI", 0x000D, 0x000D, total_len)
        payload = struct.pack("<I", json_len) + meta_json + struct.pack("<I", zip_len)
        try:
            self.keepalive_pause.set()
            self._tx(header, note=f"UPLOAD HEADER 000D/000D total_len={total_len}")
            self._tx(payload, note=f"UPLOAD META json_len={json_len} zip_len={zip_len} (no zip yet)")
            CHUNK = 4096
            sent = 0
            t0 = time.time()
            while sent < zip_len and self.sock and self.running:
                chunk = zip_bytes[sent:sent + CHUNK]
                with self.sock_lock: self.sock.sendall(chunk)
                sent += len(chunk)
            dt = time.time() - t0
            self._log(f"TX {zip_len} bytes ZIP DATA (stream) in {dt:.2f}s\n")
            self._log("[*] Upload inviato con formato sniff 0x000D/0x000D.\n")
        except Exception as e:
            self._log(f"[!] Errore upload: {e}\n")
        finally:
            self.keepalive_pause.clear()

    # ---------- MODULES window ----------
    def show_modules_window(self):
        if not self._structure_json or not self._structure_json.get("STRUCTURE"):
            messagebox.showinfo("Moduli", "Nessuna struttura ancora ricevuta (03E9).")
            return
        if self._modules_win is not None and self._modules_win.winfo_exists():
            self._modules_win.lift()
            self._rebuild_modules_window()
            return
        win = tk.Toplevel(self)
        win.title("Moduli riconosciuti")
        win.geometry("560x650")
        self._modules_win = win
        container = ttk.Frame(win, padding=8)
        container.pack(fill="both", expand=True)
        canvas = tk.Canvas(container, highlightthickness=0)
        vsb = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = ttk.Frame(canvas)
        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        def _on_configure(_evt=None): canvas.configure(scrollregion=canvas.bbox("all"))
        def _on_canvas_configure(evt): canvas.itemconfigure(inner_id, width=evt.width)
        inner.bind("<Configure>", _on_configure)
        canvas.bind("<Configure>", _on_canvas_configure)
        hdr = ttk.Frame(inner)
        hdr.pack(fill="x", pady=(0, 8))
        ttk.Label(hdr, text="mIndex", width=6).grid(row=0, column=0, sticky="w")
        ttk.Label(hdr, text="Modulo", width=16).grid(row=0, column=1, sticky="w")
        ttk.Label(hdr, text="Opzioni").grid(row=0, column=2, sticky="w")
        ttk.Button(hdr, text="Blocca tutte le sfere", command=lambda: self._on_lock_all_pressed(1)).grid(row=0, column=3, padx=(12, 4))
        ttk.Button(hdr, text="Sblocca tutte", command=lambda: self._on_lock_all_pressed(0)).grid(row=0, column=4, padx=(4, 0))
        sep = ttk.Separator(inner, orient="horizontal")
        sep.pack(fill="x", pady=(0, 8))
        self._modules_inner_frame = inner
        self._rebuild_modules_window()
        def _on_close():
            try: self._modules_widgets = {}
            except Exception: pass
            self._modules_win = None
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", _on_close)

    def _rebuild_modules_window(self):
        if self._modules_win is None or not self._modules_win.winfo_exists(): return
        if not self._structure_json: return
        inner = getattr(self, "_modules_inner_frame", None)
        if inner is None: return
        children = inner.winfo_children()
        if len(children) > 2:
            for w in children[2:]:
                try: w.destroy()
                except Exception: pass
        self._modules_widgets = {}
        mods = []
        for n in self._structure_json.get("STRUCTURE", []):
            try: mi = int(n.get("mIndex", -1))
            except Exception: continue
            if mi <= 0: continue
            mods.append(n)
        mods.sort(key=lambda x: int(x.get("mIndex", 0)))
        for row_i, n in enumerate(mods, start=0):
            m_index = int(n.get("mIndex", 0))
            t = int(n.get("type", 0))
            name = TYPE_NAMES.get(t, f"Type {t}")
            row = ttk.Frame(inner)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=str(m_index), width=6).grid(row=0, column=0, sticky="w")
            ttk.Label(row, text=f"{name} (type {t})", width=18).grid(row=0, column=1, sticky="w")
            opt = ttk.Frame(row)
            opt.grid(row=0, column=2, sticky="w")
            # Bottone Blink
            ttk.Button(opt, text="💡 Blink", width=8, 
                       command=lambda mi=m_index: self.send_blink_command(mi)).pack(side="left", padx=5)
            wrec = {"type": t, "angle_var": None, "lock_var": None}
            if t == 1:
                ang = tk.StringVar(value=f"{float(n.get('angle', 0.0)):.3f}°")
                ttk.Label(opt, text="angolo:").pack(side="left")
                ttk.Label(opt, textvariable=ang, width=10).pack(side="left", padx=(4, 10))
                lock_var = tk.IntVar(value=0)
                cb = ttk.Checkbutton(opt, text="bloccata", variable=lock_var, command=lambda mi=m_index, v=lock_var: self._on_lock_toggle(mi, v))
                cb.pack(side="left")
                wrec["angle_var"] = ang
                wrec["lock_var"] = lock_var
            else: ttk.Label(opt, text="(opzioni in arrivo)").pack(side="left")
            self._modules_widgets[m_index] = wrec
        self._update_modules_window_angles()

    def _update_modules_window_angles(self):
        if self._modules_win is None or not self._modules_win.winfo_exists(): return
        if not self._structure_by_index: return
        for mi, wrec in self._modules_widgets.items():
            if wrec.get("type") == 1 and wrec.get("angle_var") is not None:
                node = self._structure_by_index.get(mi)
                if node is not None:
                    try: wrec["angle_var"].set(f"{float(node.get('angle', 0.0)):.3f}°")
                    except Exception: pass

    def _on_lock_toggle(self, m_index: int, lock_var: tk.IntVar):
        val = 1 if int(lock_var.get()) else 0
        self.send_lock_command(m_index, val)
    
    def send_blink_command(self, m_index):
        """
        Fa lampeggiare SOLO m_index.
        Usa matchType=6 (Confermato) per gli altri e matchType=0 (Target) per quello scelto.
        """
        if not self.sock: return
        if not self._structure_json or "STRUCTURE" not in self._structure_json:
            self._log("[!] Impossibile lampeggiare: Struttura non letta.\n")
            return

        import copy
        current_list = copy.deepcopy(self._structure_json["STRUCTURE"])
        
        # LOGICA DEI FLAG (Reverse Engineering):
        # matchType 0: Target Attivo (Lampeggia)
        # matchType 6: Modulo Confermato/Stabile (Fisso o spento)
        
        for item in current_list:
            mid = int(item.get("mIndex", -1))
            
            if mid == m_index:
                item["matchType"] = 0  # TARGET -> Blink
            else:
                item["matchType"] = 6  # ALTRI  -> Stabili (Ignora)

        payload_dict = {
            "jsonType": 105,
            "matchState": 1,       # 1 = Modalità Guida Attiva
            "mIndex": int(m_index),
            "list": current_list
        }
        
        try:
            json_str = json.dumps(payload_dict, separators=(',', ':'))
            json_bytes = json_str.encode('utf-8')
            header = struct.pack("<HHI", 0x0009, 0x00B3, len(json_bytes))
            self._tx(header + json_bytes, note=f"BLINK ID {m_index} (Type 0/6)")
            self._log(f"[*] Blink ID {m_index} (Altri impostati a matchType=6)\n")
        except Exception as e:
            self._log(f"[!] Errore Blink: {e}\n")

    def send_lock_command(self, m_index: int, locked: int):
        if not self.sock:
            self._log("[!] Non connesso: impossibile inviare lock/unlock.\n")
            return
        try:
            cmd = self._f8_cmd_counter & 0xFFFF
            self._f8_cmd_counter = (self._f8_cmd_counter + 1) & 0xFFFF
            payload = bytes([int(m_index) & 0xFF, int(locked) & 0xFF])
            frame = pack_std(0x03F8, cmd, payload)
            self._tx(frame, note=f"STD 03F8/0x{cmd:04X} payload={m_index:02X}{locked:02X}")
            self._log(f"[*] {'Blocco' if locked else 'Sblocco'} modulo mIndex={m_index} (cmd=0x{cmd:04X}).\n")
        except Exception as e:
            self._log(f"[!] Errore invio lock/unlock: {e}\n")

    def _on_lock_all_pressed(self, locked: int):
        if not self._structure_json or not self._structure_json.get("STRUCTURE"):
            self._log("[!] Nessuna struttura disponibile per il blocco totale.\n")
            return
        if not self.sock:
            self._log("[!] Non connesso: impossibile inviare lock/unlock totale.\n")
            return
        max_mi = 0
        for n in self._structure_json.get("STRUCTURE", []):
            try:
                mi = int(n.get("mIndex", 0))
                if mi > max_mi: max_mi = mi
            except Exception: pass
        if max_mi <= 0:
            self._log("[!] Struttura vuota: nessun modulo da bloccare.\n")
            return
        cmd = 0x01C8 if locked else 0x019C
        payload = bytearray()
        for mi in range(1, max_mi + 1):
            payload.append(mi & 0xFF)
            payload.append(1 if locked else 0)
        frame = pack_std(0x03F8, cmd, bytes(payload))
        self._tx(frame, note=f"STD 03F8 bulk cmd=0x{cmd:04X} len={len(payload)}")
        self._log(f"[*] {'Bloccate' if locked else 'Sbloccate'} TUTTE (1..{max_mi}) via bulk cmd=0x{cmd:04X}.\n")
        try:
            for mi, wrec in (self._modules_widgets or {}).items():
                if wrec.get("type") == 1 and wrec.get("lock_var") is not None:
                    wrec["lock_var"].set(1 if locked else 0)
        except Exception: pass

    # --- NUOVI METODI PER MAPPATURA JOYSTICK ---

    def _send_smart_servo_pos(self, mid, val_float):
        """Genera pacchetto F003 per muovere servo (Type 1)."""
        # val_float: da -1.0 a 1.0 (input stick)
        # Mappiamo su un range di +/- 90 gradi (Raw 1024 a 3072, Centro 2048)
        center = 2048
        # Inverti segno se necessario per la direzione naturale
        raw_offset = int(val_float * 1024) 
        target = center - raw_offset
        target = max(0, min(4096, target)) # Clamp
        
        # Hex Structure: [ID] [Mode=02] [Time=50ms] [RawLo] [RawHi]
        t_ms = 50 
        payload = struct.pack("<BBHH", mid, 0x02, t_ms, int(target))
        
        # Invio (usa cmd counter std)
        self._tx(pack_std(0x03F0, self._next_cmd(), payload))

    def _send_gripper_toggle(self, mid):
        """Genera pacchetto C800 per pinza (Type 6)."""
        # Toggle stato
        curr = self.gripper_states.get(mid, 0) # Default 0 (Chiuso)
        new_state = 1 if curr == 0 else 0
        self.gripper_states[mid] = new_state
        
        # Hex Structure: [ID] [Type=06] [State=0/1]
        payload = bytes([mid, 0x06, new_state])
        
        # Invio
        self._tx(pack_std(0x00C8, self._next_cmd(), payload), f"Gripper {mid}->{new_state}")

    def _process_mapped_input(self, input_map):
        if not self.joy_mapping: return

        for key, target in self.joy_mapping.items():
            mid = target["id"]
            m_type = target["type"]
            val = input_map.get(key)
            if val is None: continue

            # --- STICK / TRIGGER ---
            if "AXIS" in key or "TRIG" in key:
                if isinstance(val, bool): val = 1.0 if val else 0.0
                if abs(val) < 0.1: val = 0.0 
                
                if m_type == 1: 
                    l_min = target.get("min"); l_max = target.get("max")
                    is_inc = target.get("incremental", False)
                    real_min = l_min if l_min is not None else 0
                    real_max = l_max if l_max is not None else 4096
                    if real_min > real_max: real_min, real_max = real_max, real_min

                    target_final = 2048

                    if is_inc:
                         # Modo Incrementale
                         if mid not in self.joy_incremental_accumulators:
                             start_val = self.joy_base_angles.get(mid, 2048)
                             self.joy_incremental_accumulators[mid] = float(start_val)
                         
                         speed_factor = self.joy_servo_speed.get() * 0.5 
                         change = val * speed_factor
                         current = self.joy_incremental_accumulators[mid]
                         new_val = max(real_min, min(real_max, current + change))
                         self.joy_incremental_accumulators[mid] = new_val
                         target_final = int(new_val)
                    else:
                        # Modo Standard
                        base_raw = self.joy_base_angles.get(mid, 2048)
                        if l_min is not None or l_max is not None:
                             if val > 0: offset = int(val * max(0, real_max - base_raw))
                             else: offset = int(val * max(0, base_raw - real_min))
                        else:
                             offset = int(val * 682)
                        
                        target_calc = base_raw + offset
                        target_final = int(max(real_min, min(real_max, target_calc)))
                        self.joy_incremental_accumulators[mid] = float(target_final)

                    # Invio
                    last_val = self.joy_last_sent_values.get(mid, -1)
                    if abs(target_final - last_val) < 3: continue 
                    self.joy_last_sent_values[mid] = target_final
                    t_ms = 50 
                    pl = struct.pack("<BBHH", mid, 0x02, t_ms, target_final)
                    self._tx(pack_std(0x03F0, self._next_cmd(), pl))

            # --- BOTTONI (TUTTI: DPAD, ABXY, START, BACK, THUMBS, SHOULDERS) ---
            elif "BTN" in key or "PAD" in key:
                is_pressed = False
                if isinstance(val, float): is_pressed = val > 0.5
                else: is_pressed = bool(val)
                state_key = f"{key}_{mid}"
                prev = self.button_prev_state.get(state_key, False)
                
                if m_type == 1:
                    is_inc = target.get("incremental", False)
                    if is_inc and is_pressed:
                        direction = 1.0
                        # Lista completa tasti che fanno "Diminuire" l'angolo
                        neg_keys = ["DOWN", "LEFT", "BTN_A", "BTN_X", "BTN_LB", "BTN_BACK", "BTN_THUMB_L"]
                        if any(k in key for k in neg_keys): direction = -1.0
                        
                        if mid not in self.joy_incremental_accumulators:
                            start_val = self.joy_base_angles.get(mid, 2048)
                            self.joy_incremental_accumulators[mid] = float(start_val)
                        
                        speed_factor = self.joy_servo_speed.get() * 0.5
                        change = direction * speed_factor
                        current = self.joy_incremental_accumulators[mid]
                        
                        l_min = target.get("min"); l_max = target.get("max")
                        real_min = l_min if l_min is not None else 0
                        real_max = l_max if l_max is not None else 4096
                        if real_min > real_max: real_min, real_max = real_max, real_min
                        
                        new_val = max(real_min, min(real_max, current + change))
                        self.joy_incremental_accumulators[mid] = new_val
                        target_final = int(new_val)
                        
                        last_val = self.joy_last_sent_values.get(mid, -1)
                        if abs(target_final - last_val) >= 3:
                            self.joy_last_sent_values[mid] = target_final
                            t_ms = 50
                            pl = struct.pack("<BBHH", mid, 0x02, t_ms, target_final)
                            self._tx(pack_std(0x03F0, self._next_cmd(), pl))

                elif m_type == 6:
                    if is_pressed and not prev: self._send_gripper_toggle(mid)
                
                self.button_prev_state[state_key] = is_pressed

# --- NUOVA CLASSE POPUP PER LIMITI ---
class ServoLimitDialog(tk.Toplevel):
    def __init__(self, parent, app_ref, mid, current_limits):
        super().__init__(parent)
        self.app = app_ref
        self.mid = mid
        self.title(f"Config ID {mid}")
        self.geometry("350x380") 
        
        # Recupera valori esistenti o None
        self.min_val = current_limits.get("min")
        self.max_val = current_limits.get("max")
        
        # Recupera booleano (False se non esiste)
        inc_status = bool(current_limits.get("incremental", False))
        self.inc_val = tk.BooleanVar(value=inc_status)
        
        # Intestazione
        head = ttk.Frame(self)
        head.pack(fill="x", pady=10)
        ttk.Label(head, text=f"Configura ID {mid}", font=("Arial", 11, "bold")).pack(side="left", padx=10)
        ttk.Button(head, text="🔓 Sblocca", command=self.unlock_motor).pack(side="right", padx=10)
        
        # --- SEZIONE MODALITÀ ---
        f_mode = ttk.LabelFrame(self, text="Modalità Joystick")
        f_mode.pack(fill="x", padx=10, pady=5)
        
        cb = ttk.Checkbutton(f_mode, text="Modalità Incrementale", variable=self.inc_val)
        cb.pack(anchor="w", padx=10, pady=5)
        
        ttk.Label(f_mode, text="Attivo: La leva fa da acceleratore.\nRilascio: Il motore resta in posizione.", 
                  font=("Arial", 8), foreground="gray").pack(anchor="w", padx=25)
        # ------------------------
        
        # Frame Min
        f_min = ttk.LabelFrame(self, text="Limite Minimo")
        f_min.pack(fill="x", padx=10, pady=5)
        self.lbl_min = ttk.Label(f_min, text=f"Val: {self.min_val if self.min_val is not None else '0'}")
        self.lbl_min.pack(side="left", padx=5)
        ttk.Button(f_min, text="Salva Attuale", command=self.set_min).pack(side="right", padx=5)
        
        # Frame Max
        f_max = ttk.LabelFrame(self, text="Limite Massimo")
        f_max.pack(fill="x", padx=10, pady=5)
        self.lbl_max = ttk.Label(f_max, text=f"Val: {self.max_val if self.max_val is not None else '4096'}")
        self.lbl_max.pack(side="left", padx=5)
        ttk.Button(f_max, text="Salva Attuale", command=self.set_max).pack(side="right", padx=5)

        # Pulsanti Chiusura
        f_btns = ttk.Frame(self)
        f_btns.pack(pady=15)
        ttk.Button(f_btns, text="Reset Tutto", command=self.reset_limits).pack(side="left", padx=5)
        ttk.Button(f_btns, text="Salva e Esci", command=self.save_and_close).pack(side="left", padx=5)
        
        self.result = None

    def unlock_motor(self):
        try:
            payload = bytes([self.mid, 0])
            self.app._tx(struct.pack("<HHI", 0x03F8, self.app._next_cmd(), 2) + payload)
        except: pass

    def _get_current_raw(self):
        if self.mid in self.app._structure_by_index:
            deg = float(self.app._structure_by_index[self.mid].get("angle", 0.0))
            return int((deg % 360.0) / 360.0 * 4096.0) & 0xFFFF
        return 0

    def set_min(self):
        self.min_val = self._get_current_raw()
        self.lbl_min.config(text=f"Val: {self.min_val}")

    def set_max(self):
        self.max_val = self._get_current_raw()
        self.lbl_max.config(text=f"Val: {self.max_val}")

    def reset_limits(self):
        self.min_val = None; self.max_val = None
        self.lbl_min.config(text="Val: 0"); self.lbl_max.config(text="Val: 4096")
        self.inc_val.set(False)

    def save_and_close(self):
        # Qui prepariamo il pacchetto dati per la finestra principale
        self.result = {
            "min": self.min_val, 
            "max": self.max_val,
            "incremental": self.inc_val.get() # Importante: .get() legge True/False
        }
        self.destroy()

class JoystickMapWindow(tk.Toplevel):
    def __init__(self, parent, app_ref):
        super().__init__(parent)
        self.app = app_ref
        self.title("Mappatura Controller COMPLETA")
        self.geometry("950x750") # Finestra più grande
        
        self.temp_limits = {} 

        # --- SLIDER VELOCITÀ SERVI ---
        top_frame = ttk.LabelFrame(self, text="Impostazioni Globali Mappatura", padding=10)
        top_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(top_frame, text="Velocità Incrementale Servi:").pack(side="left", padx=5)
        scale_speed = tk.Scale(top_frame, from_=1, to=100, orient="horizontal", 
                               variable=self.app.joy_servo_speed, length=300)
        scale_speed.pack(side="left", padx=10)
        # -------------------------------------
        
        # 1. Recupera i moduli
        self.available_modules = ["Nessuno"]
        if self.app._structure_by_index:
            for mid in sorted(self.app._structure_by_index.keys()):
                data = self.app._structure_by_index[mid]
                m_type = data.get("type", 0)
                type_name = TYPE_NAMES.get(m_type, f"Type {m_type}")
                self.available_modules.append(f"ID {mid} ({type_name})")
        
        # 2. Canvas
        self.canvas = tk.Canvas(self, width=800, height=500, bg="white")
        self.canvas.pack(pady=10)
        
        self.img_ref = None
        try:
            self.img_ref = tk.PhotoImage(file="controller.png") 
            self.canvas.create_image(400, 250, image=self.img_ref)
        except Exception:
            self.canvas.create_text(400, 250, text="[Manca controller.png]", fill="red")

        # 3. COORDINATE COMPLETE (TUTTI I TASTI)
        self.coords = {
            # --- ASSI ---
            "AXIS_LX": (133, 212), "AXIS_LY": (133, 152),
            "AXIS_RX": (663, 394), "AXIS_RY": (663, 333),
            "TRIG_L": (325, 81),   "TRIG_R": (470, 81),
            
            # --- BOTTONI FRONTALI ---
            "BTN_A": (648, 230),   "BTN_B": (648, 201),
            "BTN_X": (648, 171),   "BTN_Y": (648, 142),
            
            # --- DPAD ---
            "PAD_UP": (134, 319),  "PAD_DOWN": (134, 408),
            "PAD_LEFT": (134, 377), "PAD_RIGHT": (134, 347),
            
            # --- [NUOVI] SPALLE (SHOULDERS) ---
            "BTN_LB": (147, 96),   "BTN_RB": (647, 96),
            
            # --- [NUOVI] CENTRALI (START/BACK) ---
            "BTN_BACK": (145, 275), "BTN_START": (645, 275),
            
            # --- [NUOVI] STICK CLICKS (THUMBS) ---
            "BTN_THUMB_L": (397, 156),  # A sinistra dello stick SX
            "BTN_THUMB_R": (396, 383)  # A destra dello stick DX
        }
        
        self.combos = {}
        self.settings_btns = {}
        
        # 4. Generazione UI
        for key, (x, y) in self.coords.items():
            # Aggiungo etichetta per chiarezza sui tasti nuovi
            #lbl = self.canvas.create_text(x, y-15, text=key.replace("BTN_","").replace("AXIS_",""), font=("Arial", 7, "bold"), fill="#555")
            
            cb = ttk.Combobox(self.canvas, values=self.available_modules, width=13, state="readonly")
            
            curr = self.app.joy_mapping.get(key)
            if curr:
                for item in self.available_modules:
                    if item.startswith(f"ID {curr['id']} "):
                        cb.set(item)
                        break
                self.temp_limits[key] = {
                    "min": curr.get("min"),
                    "max": curr.get("max"),
                    "incremental": curr.get("incremental", False)
                }
            else:
                cb.set("Nessuno")
                
            self.canvas.create_window(x, y, window=cb)
            self.combos[key] = cb
            
            cb.bind("<<ComboboxSelected>>", lambda e, k=key: self.on_combo_change(k))
            btn = ttk.Button(self.canvas, text="⚙", width=2, command=lambda k=key: self.open_limit_settings(k))
            self.settings_btns[key] = {"widget": btn, "win_id": None, "x": x+75, "y": y}
            
            self.on_combo_change(key)

        ttk.Button(self, text="Salva Configurazione", command=self.save_map).pack(pady=10)

        # --- DEBUG: TROVA COORDINATE (Tutto dentro __init__) ---
        def on_canvas_click(event):
            x, y = event.x, event.y
            print(f"Coordinate cliccate: ({x}, {y})") # GUARDA LA CONSOLE QUI
            
            # Pallino rosso di conferma
            r = 5
            self.canvas.create_oval(x-r, y-r, x+r, y+r, fill="red", outline="yellow")

        # Collega il click
        self.canvas.bind("<Button-1>", on_canvas_click)    
        # -------------------------------------------------------

    # ... (Il resto dei metodi on_combo_change, open_limit_settings, save_map RIMANE UGUALE) ...
    # Assicurati di copiare i metodi esistenti qui sotto se sostituisci l'intera classe.
    def on_combo_change(self, key):
        cb = self.combos[key]
        val = cb.get()
        btn_data = self.settings_btns[key]
        show_btn = "Type 1" in val or "Sfera" in val
        if show_btn:
            if btn_data["win_id"] is None:
                btn_data["win_id"] = self.canvas.create_window(btn_data["x"], btn_data["y"], window=btn_data["widget"])
        else:
            if btn_data["win_id"] is not None:
                self.canvas.delete(btn_data["win_id"])
                btn_data["win_id"] = None

    def open_limit_settings(self, key):
        cb = self.combos[key]
        val = cb.get()
        try:
            mid = int(val.split(" ")[1])
            curr_limits = self.temp_limits.get(key, {})
            dlg = ServoLimitDialog(self, self.app, mid, curr_limits)
            self.wait_window(dlg)
            if dlg.result:
                self.temp_limits[key] = dlg.result
        except Exception: pass

    def save_map(self):
        new_map = {}
        for key, cb in self.combos.items():
            val = cb.get()
            if val and val != "Nessuno":
                try:
                    parts = val.split(" ")
                    mid = int(parts[1])
                    m_type = 0
                    if mid in self.app._structure_by_index:
                        m_type = self.app._structure_by_index[mid].get("type", 0)
                    limits = self.temp_limits.get(key, {})
                    new_map[key] = {
                        "id": mid, "type": m_type,
                        "min": limits.get("min"), "max": limits.get("max"),
                        "incremental": limits.get("incremental", False)
                    }
                except: pass
        self.app.joy_mapping = new_map
        self.app._log(f"[MAP] Salvata: {len(new_map)} controlli.\n")
        self.destroy()
        


    # ============================================================
    # SSH TOOL (inject public key + enable sshd + dump via scp)
    # ============================================================
    def open_ssh_tool_window(self):
        """Apri la finestra 'SSH tool' (iniezione public key + abilita ssh + dump scp)."""
        try:
            if getattr(self, "_ssh_tool_win", None) is not None and self._ssh_tool_win.winfo_exists():
                self._ssh_tool_win.lift()
                self._ssh_tool_win.focus_force()
                return
        except Exception:
            pass

        win = tk.Toplevel(self)
        self._ssh_tool_win = win
        win.title("SSH tool")
        win.geometry("980x620")

        container = ttk.Frame(win, padding=10)
        container.pack(fill="both", expand=True)

        # --- Sezione inject public key / enable sshd ---
        sec = ttk.LabelFrame(container, text="SSH: inietta public key / abilita sshd")
        sec.pack(fill="x")

        self.ssh_pubkey_path_var = tk.StringVar(value="")
        ttk.Label(sec, text="Public key (.pub):").grid(row=0, column=0, sticky="w", padx=5, pady=6)
        ttk.Entry(sec, textvariable=self.ssh_pubkey_path_var, width=72).grid(row=0, column=1, sticky="w", padx=5, pady=6)

        ttk.Button(sec, text="…", command=self._ssh_tool_pick_pubkey).grid(row=0, column=2, sticky="w", padx=5, pady=6)

        self.ssh_nc_port_var = tk.IntVar(value=2222)

        ttk.Button(sec, text="inietta publikey", command=self._ssh_tool_inject_pubkey).grid(row=0, column=3, sticky="w", padx=10, pady=6)
        ttk.Button(sec, text="abilita ssh", command=self._ssh_tool_enable_ssh).grid(row=0, column=4, sticky="w", padx=10, pady=6)

        ttk.Label(sec, text="(usa nc verso porta 2222; IP preso dalla schermata principale)").grid(row=1, column=0, columnspan=5, sticky="w", padx=5, pady=(0,6))

        # --- Dump via SCP (presa da sshenabler) ---
        dump = ttk.LabelFrame(container, text="Dump via SCP")
        dump.pack(fill="x", pady=10)

        self.ssh_tool_ssh_port_var = tk.IntVar(value=22)
        default_key = os.path.join(os.path.expanduser("~"), "clicbot_key")
        self.ssh_tool_key_path_var = tk.StringVar(value=default_key)
        self.ssh_tool_remote_path_var = tk.StringVar(value="/userdata")
        self.ssh_tool_local_dir_var = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Desktop"))

        ttk.Label(dump, text="Porta SSH:").grid(row=0, column=0, sticky="w", padx=5, pady=6)
        ttk.Entry(dump, textvariable=self.ssh_tool_ssh_port_var, width=8).grid(row=0, column=1, sticky="w", padx=5, pady=6)

        ttk.Label(dump, text="Chiave (-i):").grid(row=0, column=2, sticky="w", padx=5, pady=6)
        ttk.Entry(dump, textvariable=self.ssh_tool_key_path_var, width=44).grid(row=0, column=3, sticky="w", padx=5, pady=6)
        ttk.Button(dump, text="…", command=self._ssh_tool_pick_key).grid(row=0, column=4, padx=5, pady=6, sticky="w")

        ttk.Label(dump, text="Cartella remota:").grid(row=1, column=0, sticky="w", padx=5, pady=6)
        ttk.Entry(dump, textvariable=self.ssh_tool_remote_path_var, width=28).grid(row=1, column=1, sticky="w", padx=5, pady=6)

        ttk.Label(dump, text="Destinazione locale:").grid(row=1, column=2, sticky="w", padx=5, pady=6)
        ttk.Entry(dump, textvariable=self.ssh_tool_local_dir_var, width=44).grid(row=1, column=3, sticky="w", padx=5, pady=6)
        ttk.Button(dump, text="…", command=self._ssh_tool_pick_local_dir).grid(row=1, column=4, padx=5, pady=6, sticky="w")

        self.btn_ssh_tool_dump = ttk.Button(dump, text="Dump (scp -r)", command=self._ssh_tool_dump_flow)
        self.btn_ssh_tool_dump.grid(row=0, column=5, rowspan=2, padx=10, pady=6, sticky="nsw")

        # --- Log finestra ---
        logf = ttk.LabelFrame(container, text="Log SSH tool")
        logf.pack(fill="both", expand=True)

        self._ssh_tool_log = tk.Text(logf, height=18, wrap="none")
        self._ssh_tool_log.pack(fill="both", expand=True)

        self._ssh_tool_log_write("Pronto.\n- 'inietta publikey' prepara /root/.ssh/authorized_keys e riavvia sshd\n- 'abilita ssh' avvia solo /usr/sbin/sshd\n- 'Dump (scp -r)' scarica la cartella remota su PC\n\n")

        def _on_close():
            try:
                self._ssh_tool_win = None
            except Exception:
                pass
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", _on_close)

    def _ssh_tool_log_write(self, s: str):
        try:
            if getattr(self, "_ssh_tool_log", None) is not None and self._ssh_tool_log.winfo_exists():
                self._ssh_tool_log.insert("end", s)
                self._ssh_tool_log.see("end")
        except Exception:
            pass
        # duplica anche nel log principale (comodo per debug)
        try:
            self._log("[SSH TOOL] " + s)
        except Exception:
            pass

    def _ssh_tool_pick_pubkey(self):
        p = filedialog.askopenfilename(title="Scegli public key (.pub)", filetypes=[("Public key", "*.pub"), ("All files", "*.*")])
        if p:
            self.ssh_pubkey_path_var.set(p)

    def _ssh_tool_pick_key(self):
        p = filedialog.askopenfilename(title="Scegli chiave privata", filetypes=[("All files", "*.*")])
        if p:
            self.ssh_tool_key_path_var.set(p)

    def _ssh_tool_pick_local_dir(self):
        p = filedialog.askdirectory(title="Scegli cartella di destinazione")
        if p:
            self.ssh_tool_local_dir_var.set(p)

    def _ssh_tool_nc_send(self, ip: str, port: int, command: str, timeout_s: float = 6.0) -> str:
        """
        Esegue: nc ip port  -> invia 'command\n' e ritorna l'output letto (se presente).
        """
        self._ssh_tool_log_write(f"[*] nc -> {ip}:{port}\n    cmd: {command}\n")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        out = ""
        try:
            s.connect((ip, int(port)))
            payload = (command.strip() + "\n").encode("utf-8", errors="ignore")
            s.sendall(payload)
            time.sleep(0.25)
            try:
                data = s.recv(65535)
                if data:
                    out = data.decode("utf-8", errors="ignore")
            except Exception:
                pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        if out:
            self._ssh_tool_log_write("[*] nc RX:\n" + out + "\n")
        return out

    def _ssh_tool_inject_pubkey(self):
        def worker():
            ip = self.ip_var.get().strip()
            port = int(getattr(self, "ssh_nc_port_var", tk.IntVar(value=2222)).get())
            pub_path = (self.ssh_pubkey_path_var.get() or "").strip()

            if not ip:
                self._ssh_tool_log_write("[!] IP Robot vuoto.\n")
                return
            if not pub_path or not os.path.isfile(pub_path):
                self._ssh_tool_log_write("[!] Seleziona un file .pub valido.\n")
                return

            try:
                pub = open(pub_path, "r", encoding="utf-8", errors="ignore").read().strip()
            except Exception as e:
                self._ssh_tool_log_write(f"[!] Errore lettura .pub: {e}\n")
                return

            if not pub or "ssh-" not in pub:
                self._ssh_tool_log_write("[!] Contenuto .pub non sembra una chiave SSH valida.\n")
                return

            # Escape robusto per eventuali apici (raro, ma meglio)
            pub_escaped = pub.replace("'", "'\"'\"'")

            # Sequenza richiesta (in un unico comando shell)
            cmd = (
                "mkdir -p /root/.ssh; "
                "chmod 700 /root/.ssh; "
                "printf '%s\n' '" + pub_escaped + "' >> /root/.ssh/authorized_keys; "
                "chmod 600 /root/.ssh/authorized_keys; "
                "cat /root/.ssh/authorized_keys; "
                "pkill sshd; "
                "/usr/sbin/sshd"
            )

            try:
                self._ssh_tool_nc_send(ip, port, cmd)
                self._ssh_tool_log_write("[+] Public key iniettata e sshd riavviato.\n")
            except Exception as e:
                self._ssh_tool_log_write(f"[!] Errore inject: {e}\n")

        threading.Thread(target=worker, daemon=True).start()

    def _ssh_tool_enable_ssh(self):
        def worker():
            ip = self.ip_var.get().strip()
            port = int(getattr(self, "ssh_nc_port_var", tk.IntVar(value=2222)).get())
            if not ip:
                self._ssh_tool_log_write("[!] IP Robot vuoto.\n")
                return
            try:
                self._ssh_tool_nc_send(ip, port, "/usr/sbin/sshd")
                self._ssh_tool_log_write("[+] Comando sshd inviato.\n")
            except Exception as e:
                self._ssh_tool_log_write(f"[!] Errore abilita ssh: {e}\n")

        threading.Thread(target=worker, daemon=True).start()

    def _ssh_tool_dump_flow(self):
        def worker():
            ip = self.ip_var.get().strip()
            port = int(self.ssh_tool_ssh_port_var.get())
            key = (self.ssh_tool_key_path_var.get() or "").strip()
            remote = (self.ssh_tool_remote_path_var.get() or "").strip()
            local_base = (self.ssh_tool_local_dir_var.get() or "").strip()

            if not ip:
                self._ssh_tool_log_write("[!] IP Robot vuoto.\n")
                return
            if not remote.startswith("/"):
                self._ssh_tool_log_write("[!] La cartella remota deve iniziare con '/'. Esempio: /userdata\n")
                return
            if not os.path.isdir(local_base):
                self._ssh_tool_log_write("[!] Destinazione locale non valida.\n")
                return
            if not key:
                self._ssh_tool_log_write("[!] Seleziona la chiave privata (-i).\n")
                return

            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(local_base, f"clicbot_dump_{ts}")
            os.makedirs(dest, exist_ok=True)

            cmd = [
                "scp",
                "-P", str(port),
                "-i", key,
                "-r",
                f"root@{ip}:{remote}",
                dest
            ]

            self._ssh_tool_log_write("[*] Avvio dump...\n")
            self._ssh_tool_log_write("    " + " ".join(cmd) + "\n")

            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            except FileNotFoundError:
                self._ssh_tool_log_write("[!] scp non trovato. Installa OpenSSH Client (Windows) o usa scp da Git/WSL.\n")
                return
            except Exception as e:
                self._ssh_tool_log_write(f"[!] Errore avvio scp: {e}\n")
                return

            try:
                while True:
                    line = p.stdout.readline() if p.stdout else ""
                    if not line:
                        break
                    self._ssh_tool_log_write(line)
            except Exception:
                pass

            rc = p.wait()
            if rc == 0:
                self._ssh_tool_log_write(f"[+] Dump completato in: {dest}\n")
            else:
                self._ssh_tool_log_write(f"[!] Dump finito con errore (exit code {rc}).\n")

        threading.Thread(target=worker, daemon=True).start()

# Backward-compatibility fix:
# SSH tool methods are defined in JoystickMapWindow, but App uses them directly.
# Bind them to App if missing, so App can use the SSH tool button safely.
_SSH_TOOL_METHODS = (
    "open_ssh_tool_window",
    "_ssh_tool_log_write",
    "_ssh_tool_pick_pubkey",
    "_ssh_tool_pick_key",
    "_ssh_tool_pick_local_dir",
    "_ssh_tool_nc_send",
    "_ssh_tool_inject_pubkey",
    "_ssh_tool_enable_ssh",
    "_ssh_tool_dump_flow",
)
for _m in _SSH_TOOL_METHODS:
    if not hasattr(App, _m) and hasattr(JoystickMapWindow, _m):
        setattr(App, _m, getattr(JoystickMapWindow, _m))

if __name__ == "__main__":
    App().mainloop()

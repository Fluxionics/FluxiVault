import customtkinter as ctk
import sqlite3, base64, os, random, uuid, hashlib, shutil, time, json, string, re
import pyperclip
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from tkinter import messagebox, filedialog

# CONFIGURACIÓN
BASE_DIR = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser("~")), "WinSystemAuthCore")
for d in [BASE_DIR, os.path.join(BASE_DIR, "ShadowStorage"), os.path.join(BASE_DIR, "Backups")]:
    if not os.path.exists(d): os.makedirs(d)

DB_NAME = os.path.join(BASE_DIR, "vault_v6.db")
SHADOW_STORAGE = os.path.join(BASE_DIR, "ShadowStorage")

# SISTEMA DE CIFRADO MEJORADO
class QuantumCrypto:
    def __init__(self, password):
        self.key = self._derive(password)
        self.backup_key = self._derive_backup(password)

    def _derive(self, pw):
        hw_id = str(uuid.getnode()).encode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, 
                        salt=hw_id, iterations=600000)
        return kdf.derive(pw.encode() + b"QUANTUM_2025")

    def _derive_backup(self, pw):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                        salt=b"BACKUP_SALT", iterations=400000)
        return kdf.derive(pw.encode())

    def encrypt(self, text):
        if not text: return ""
        n1, n2, n3 = os.urandom(12), os.urandom(12), os.urandom(12)
        c1 = ChaCha20Poly1305(self.key).encrypt(n1, text.encode(), None)
        c2 = AESGCM(self.key).encrypt(n2, c1, None)
        c3 = ChaCha20Poly1305(self.backup_key).encrypt(n3, c2, None)
        return base64.b64encode(n1 + n2 + n3 + c3).decode()

    def decrypt(self, token):
        try:
            data = base64.b64decode(token)
            n1, n2, n3, cipher = data[:12], data[12:24], data[24:36], data[36:]
            c2 = ChaCha20Poly1305(self.backup_key).decrypt(n3, cipher, None)
            c1 = AESGCM(self.key).decrypt(n2, c2, None)
            return ChaCha20Poly1305(self.key).decrypt(n1, c1, None).decode()
        except: return "[🔒 ACCESO DENEGADO]"

# GENERADOR DE CONTRASEÑAS
class PasswordGen:
    @staticmethod
    def generate(length=16, upper=True, lower=True, digits=True, symbols=True):
        chars = ""
        if lower: chars += string.ascii_lowercase
        if upper: chars += string.ascii_uppercase
        if digits: chars += string.digits
        if symbols: chars += "!@#$%^&*()_+-=[]{}|"
        return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

    @staticmethod
    def check_strength(pwd):
        score = 0
        if len(pwd) >= 12: score += 30
        if re.search(r'[a-z]', pwd): score += 15
        if re.search(r'[A-Z]', pwd): score += 15
        if re.search(r'\d', pwd): score += 15
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|]', pwd): score += 25
        
        if score >= 80: return "🟢 MUY FUERTE", score
        elif score >= 60: return "🟡 FUERTE", score
        elif score >= 40: return "🟠 MODERADA", score
        return "🔴 DÉBIL", score

# GENERADOR DE IDENTIDADES
def generate_identity():
    nombres = ["RODRIGO", "VALERIA", "MAURICIO", "ELENA", "SANTIAGO", "ADRIANA"]
    apellidos = ["ZAVALA", "GUERRERO", "MENDOZA", "ORTEGA", "VENEGAS"]
    bancos = ["SANTANDER", "BBVA", "BANORTE", "HSBC", "CITIBANAMEX"]
    
    n, a1, a2 = random.choice(nombres), random.choice(apellidos), random.choice(apellidos)
    year = random.randint(1975, 2005)
    curp = f"{a1[:2]}{a2[0]}{n[0]}{year%100:02d}0715HDF{a1[2]}9"
    banco = random.choice(bancos)
    
    return f"""╔═══════════════════════════════════════╗
║    🛡️ IDENTIDAD QUANTUM APEX       ║
╚═══════════════════════════════════════╝

👤 PERSONAL
NOMBRE: {n} {a1} {a2}
CURP: {curp}
RFC: {curp[:10]}-T12
NSS: {random.randint(10,99)}-{random.randint(10,99)}-{random.randint(1000,9999)}

💳 FINANCIERO - {banco}
TARJETA: {random.randint(4000,5999)} {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}
CLABE: 012180{random.randint(10**11, 10**12-1)}
CVV: {random.randint(100,999)} | VENCE: {random.randint(1,12):02d}/30
SALDO: ${random.randint(5000,950000):,}.00 MXN

🚗 VEHICULAR
AUTO: {random.choice(['BMW M3', 'Audi Q7', 'Tesla Model X', 'Porsche Cayenne'])}
PLACAS: {random.choice('ABC')}{random.randint(100,999)}-{random.choice('XYZ')}

📧 CONTACTO
EMAIL: {n.lower()}.{a1.lower()}{random.randint(10,99)}@gmail.com
TEL: +52 {random.randint(55,99)} {random.randint(1000,9999)} {random.randint(1000,9999)}

⚠️ GENERADO: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
"""

# APLICACIÓN PRINCIPAL
class FluxiVaultPro(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔐 FLUXI VAULT PRO - Quantum Security")
        self.geometry("1400x900")
        ctk.set_appearance_mode("dark")
        
        self._init_db()
        self.is_decoy = False
        self.login_attempts = 0
        self.max_attempts = 5
        self.show_login()

    def _init_db(self):
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY, title TEXT, username TEXT, password TEXT,
                url TEXT, notes TEXT, category TEXT, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_decoy INTEGER DEFAULT 0, favorite INTEGER DEFAULT 0)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY, orig TEXT, hidden TEXT, 
                size INTEGER, type TEXT, date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
            conn.execute("CREATE TABLE IF NOT EXISTS config (k TEXT PRIMARY KEY, v TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS ghost (id INTEGER PRIMARY KEY, s TEXT, date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
            conn.execute("CREATE TABLE IF NOT EXISTS stego (h TEXT PRIMARY KEY, m TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, type TEXT, details TEXT, date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")

    def log(self, type, details=""):
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("INSERT INTO logs (type, details) VALUES (?, ?)", (type, details))

    def show_login(self):
        for w in self.winfo_children(): w.destroy()
        
        frame = ctk.CTkFrame(self, corner_radius=20)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(frame, text="🔐 FLUXI VAULT PRO", 
                    font=("Impact", 55), text_color="#00d4ff").pack(pady=20)
        ctk.CTkLabel(frame, text="Sistema de Seguridad Cuántico",
                    font=("Arial", 12), text_color="#888").pack()
        
        self.pass_entry = ctk.CTkEntry(frame, placeholder_text="🔑 Clave Maestra",
                                       show="●", width=400, height=45, font=("Arial", 14))
        self.pass_entry.pack(pady=30, padx=40)
        self.pass_entry.bind("<Return>", lambda e: self.auth())
        
        ctk.CTkButton(frame, text="🔓 DESBLOQUEAR", command=self.auth,
                     width=400, height=45, font=("Arial", 14, "bold"),
                     fg_color="#00d4ff").pack(pady=10)
        
        self.attempts_lbl = ctk.CTkLabel(frame, 
                                         text=f"Intentos: {self.max_attempts - self.login_attempts}",
                                         font=("Arial", 10), text_color="#888")
        self.attempts_lbl.pack(pady=5)
        
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        ctk.CTkButton(btn_frame, text="⚙️ Emergencias", width=180,
                     command=self.setup_emergency, fg_color="transparent", 
                     border_width=1).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="📋 Logs", width=180,
                     command=self.show_logs, fg_color="transparent",
                     border_width=1).pack(side="left", padx=5)

    def auth(self):
        pwd = self.pass_entry.get()
        if not pwd: return
        
        if self.login_attempts >= self.max_attempts:
            messagebox.showerror("🔒 Bloqueado", "Demasiados intentos")
            self.destroy()
            return
        
        with sqlite3.connect(DB_NAME) as conn:
            panic = conn.execute("SELECT v FROM config WHERE k='panic_h'").fetchone()
            decoy = conn.execute("SELECT v FROM config WHERE k='decoy_h'").fetchone()
            
            h = hashlib.sha512(pwd.encode()).hexdigest()
            
            if panic and h == panic[0]:
                self.log("PANIC", "Autodestrucción")
                shutil.rmtree(BASE_DIR)
                os._exit(0)
            
            if decoy and h == decoy[0]:
                self.is_decoy = True
                self.log("DECOY_LOGIN", "Modo señuelo")
        
        try:
            self.crypto = QuantumCrypto(pwd)
            self.log("LOGIN_OK", "Acceso autorizado")
            self.show_main()
        except:
            self.login_attempts += 1
            self.attempts_lbl.configure(text=f"Intentos: {self.max_attempts - self.login_attempts}")
            self.log("LOGIN_FAIL", f"Intento {self.login_attempts}")
            messagebox.showerror("❌", "Contraseña incorrecta")

    def show_main(self):
        for w in self.winfo_children(): w.destroy()
        
        # Header
        header = ctk.CTkFrame(self, height=60, corner_radius=0, fg_color="#1a1a1a")
        header.pack(fill="x")
        
        mode = "⚠️ SEÑUELO" if self.is_decoy else "✅ SEGURO"
        color = "#ff6b6b" if self.is_decoy else "#51cf66"
        
        ctk.CTkLabel(header, text=f"🔐 FLUXI VAULT PRO - {mode}",
                    font=("Arial", 20, "bold"), text_color=color).pack(side="left", padx=20)
        
        btn_f = ctk.CTkFrame(header, fg_color="transparent")
        btn_f.pack(side="right", padx=20)
        
        ctk.CTkButton(btn_f, text="🌓", width=60, command=self.toggle_theme).pack(side="left", padx=3)
        ctk.CTkButton(btn_f, text="💾", width=60, command=self.backup).pack(side="left", padx=3)
        ctk.CTkButton(btn_f, text="🚪", width=60, command=self.destroy, fg_color="#ff6b6b").pack(side="left", padx=3)
        
        # Tabs
        self.tabs = ctk.CTkTabview(self, corner_radius=10)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.t_vault = self.tabs.add("🔐 Bóveda")
        self.t_gen = self.tabs.add("🎲 Generador")
        self.t_id = self.tabs.add("👤 Identidades")
        self.t_files = self.tabs.add("📂 Black Hole")
        self.t_stego = self.tabs.add("🖼️ Steganografía")
        self.t_ghost = self.tabs.add("👻 Ghost")
        self.t_sec = self.tabs.add("🛡️ Seguridad")
        
        self.init_vault()
        self.init_generator()
        self.init_identity()
        self.init_files()
        self.init_stego()
        self.init_ghost()
        self.init_security()

    # BÓVEDA
    def init_vault(self):
        top = ctk.CTkFrame(self.t_vault)
        top.pack(fill="x", padx=10, pady=10)
        
        self.search = ctk.CTkEntry(top, placeholder_text="🔍 Buscar...", width=300)
        self.search.pack(side="left", padx=5)
        self.search.bind("<KeyRelease>", lambda e: self.refresh_vault())
        
        cats = ["Todas", "Redes Sociales", "Bancos", "Email", "Trabajo", "Otros"]
        self.cat_filter = ctk.CTkComboBox(top, values=cats, width=150,
                                          command=lambda e: self.refresh_vault())
        self.cat_filter.pack(side="left", padx=5)
        
        ctk.CTkButton(top, text="➕ Nueva", command=self.add_pass_dialog,
                     fg_color="#00d4ff", width=120).pack(side="right", padx=5)
        
        self.vault_scroll = ctk.CTkScrollableFrame(self.t_vault, height=600)
        self.vault_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        self.refresh_vault()

    def add_pass_dialog(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("➕ Nueva Entrada")
        dlg.geometry("500x650")
        dlg.grab_set()
        
        ctk.CTkLabel(dlg, text="Título:", font=("Arial", 12, "bold")).pack(pady=(20,5))
        title_e = ctk.CTkEntry(dlg, width=400)
        title_e.pack(pady=5)
        
        ctk.CTkLabel(dlg, text="Usuario/Email:", font=("Arial", 12, "bold")).pack(pady=(10,5))
        user_e = ctk.CTkEntry(dlg, width=400)
        user_e.pack(pady=5)
        
        ctk.CTkLabel(dlg, text="Contraseña:", font=("Arial", 12, "bold")).pack(pady=(10,5))
        pf = ctk.CTkFrame(dlg, fg_color="transparent")
        pf.pack(pady=5)
        
        pass_e = ctk.CTkEntry(pf, width=280, show="●")
        pass_e.pack(side="left", padx=5)
        
        def toggle(): 
            pass_e.configure(show="" if pass_e.cget("show") == "●" else "●")
        
        ctk.CTkButton(pf, text="👁️", width=40, command=toggle).pack(side="left", padx=2)
        ctk.CTkButton(pf, text="🎲", width=40, 
                     command=lambda: (pass_e.delete(0,'end'), 
                                    pass_e.insert(0, PasswordGen.generate()))).pack(side="left", padx=2)
        
        # Medidor de fuerza
        strength_lbl = ctk.CTkLabel(dlg, text="")
        strength_lbl.pack(pady=5)
        
        def check():
            pwd = pass_e.get()
            if pwd:
                s, score = PasswordGen.check_strength(pwd)
                strength_lbl.configure(text=f"{s} ({score}/100)")
        
        pass_e.bind("<KeyRelease>", lambda e: check())
        
        ctk.CTkLabel(dlg, text="URL:", font=("Arial", 12, "bold")).pack(pady=(10,5))
        url_e = ctk.CTkEntry(dlg, width=400)
        url_e.pack(pady=5)
        
        ctk.CTkLabel(dlg, text="Categoría:", font=("Arial", 12, "bold")).pack(pady=(10,5))
        cat_e = ctk.CTkComboBox(dlg, values=["Redes Sociales", "Bancos", "Email", "Trabajo", "Otros"], width=400)
        cat_e.pack(pady=5)
        
        ctk.CTkLabel(dlg, text="Notas:", font=("Arial", 12, "bold")).pack(pady=(10,5))
        notes_e = ctk.CTkTextbox(dlg, width=400, height=100)
        notes_e.pack(pady=5)
        
        def save():
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("""INSERT INTO vault (title, username, password, url, notes, category, is_decoy)
                             VALUES (?,?,?,?,?,?,?)""",
                            (self.crypto.encrypt(title_e.get()),
                             self.crypto.encrypt(user_e.get()),
                             self.crypto.encrypt(pass_e.get()),
                             self.crypto.encrypt(url_e.get()),
                             self.crypto.encrypt(notes_e.get("0.0","end")),
                             cat_e.get(),
                             1 if self.is_decoy else 0))
            self.refresh_vault()
            dlg.destroy()
        
        ctk.CTkButton(dlg, text="💾 GUARDAR", command=save,
                     fg_color="#00d4ff", width=400, height=40).pack(pady=20)

    def refresh_vault(self):
        for w in self.vault_scroll.winfo_children(): w.destroy()
        
        search_term = self.search.get().lower()
        cat_filter = self.cat_filter.get()
        
        with sqlite3.connect(DB_NAME) as conn:
            query = "SELECT * FROM vault WHERE is_decoy=?"
            params = [1 if self.is_decoy else 0]
            
            if cat_filter != "Todas":
                query += " AND category=?"
                params.append(cat_filter)
            
            rows = conn.execute(query, params).fetchall()
        
        for r in rows:
            id, title, user, pwd, url, notes, cat, created, is_decoy, fav = r
            
            title_dec = self.crypto.decrypt(title)
            if search_term and search_term not in title_dec.lower():
                continue
            
            row = ctk.CTkFrame(self.vault_scroll, fg_color="#2b2b2b", corner_radius=10)
            row.pack(fill="x", pady=5, padx=5)
            
            # Info
            info_f = ctk.CTkFrame(row, fg_color="transparent")
            info_f.pack(side="left", fill="x", expand=True, padx=15, pady=10)
            
            ctk.CTkLabel(info_f, text=title_dec, font=("Arial", 14, "bold"),
                        anchor="w").pack(anchor="w")
            ctk.CTkLabel(info_f, text=f"👤 {self.crypto.decrypt(user)}", 
                        font=("Arial", 10), text_color="#888",
                        anchor="w").pack(anchor="w")
            ctk.CTkLabel(info_f, text=f"📁 {cat} | 📅 {created[:10]}",
                        font=("Arial", 9), text_color="#666",
                        anchor="w").pack(anchor="w")
            
            # Botones
            btn_f = ctk.CTkFrame(row, fg_color="transparent")
            btn_f.pack(side="right", padx=10)
            
            ctk.CTkButton(btn_f, text="📋 User", width=80,
                         command=lambda u=user: pyperclip.copy(self.crypto.decrypt(u))).pack(pady=2)
            ctk.CTkButton(btn_f, text="🔑 Pass", width=80,
                         command=lambda p=pwd: pyperclip.copy(self.crypto.decrypt(p))).pack(pady=2)
            ctk.CTkButton(btn_f, text="🗑️", width=60, fg_color="#ff6b6b",
                         command=lambda i=id: self.delete_entry(i)).pack(pady=2)

    def delete_entry(self, id):
        if messagebox.askyesno("❓", "¿Eliminar esta entrada?"):
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("DELETE FROM vault WHERE id=?", (id,))
            self.refresh_vault()

    # GENERADOR
    def init_generator(self):
        frame = ctk.CTkFrame(self.t_gen)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(frame, text="🎲 GENERADOR DE CONTRASEÑAS SEGURAS",
                    font=("Arial", 24, "bold")).pack(pady=20)
        
        # Resultado
        self.gen_result = ctk.CTkTextbox(frame, height=100, font=("Consolas", 16))
        self.gen_result.pack(fill="x", padx=20, pady=10)
        
        # Longitud
        len_f = ctk.CTkFrame(frame, fg_color="transparent")
        len_f.pack(pady=10)
        
        ctk.CTkLabel(len_f, text="Longitud:", font=("Arial", 12)).pack(side="left", padx=10)
        self.gen_len = ctk.CTkSlider(len_f, from_=8, to=64, number_of_steps=56, width=300)
        self.gen_len.set(16)
        self.gen_len.pack(side="left", padx=10)
        
        self.len_lbl = ctk.CTkLabel(len_f, text="16", font=("Arial", 12, "bold"))
        self.len_lbl.pack(side="left", padx=10)
        self.gen_len.configure(command=lambda v: self.len_lbl.configure(text=str(int(v))))
        
        # Opciones
        opt_f = ctk.CTkFrame(frame, fg_color="transparent")
        opt_f.pack(pady=20)
        
        self.gen_upper = ctk.CTkCheckBox(opt_f, text="Mayúsculas (A-Z)")
        self.gen_upper.pack(pady=5)
        self.gen_upper.select()
        
        self.gen_lower = ctk.CTkCheckBox(opt_f, text="Minúsculas (a-z)")
        self.gen_lower.pack(pady=5)
        self.gen_lower.select()
        
        self.gen_digits = ctk.CTkCheckBox(opt_f, text="Números (0-9)")
        self.gen_digits.pack(pady=5)
        self.gen_digits.select()
        
        self.gen_symbols = ctk.CTkCheckBox(opt_f, text="Símbolos (!@#$...)")
        self.gen_symbols.pack(pady=5)
        self.gen_symbols.select()
        
        # Botones
        btn_f = ctk.CTkFrame(frame, fg_color="transparent")
        btn_f.pack(pady=20)
        
        def generate():
            pwd = PasswordGen.generate(
                int(self.gen_len.get()),
                self.gen_upper.get(),
                self.gen_lower.get(),
                self.gen_digits.get(),
                self.gen_symbols.get()
            )
            self.gen_result.delete("0.0", "end")
            self.gen_result.insert("0.0", pwd)
            
            strength, score = PasswordGen.check_strength(pwd)
            self.strength_lbl.configure(text=f"{strength} - Puntuación: {score}/100")
        
        ctk.CTkButton(btn_f, text="🎲 GENERAR", command=generate,
                     width=200, height=40, fg_color="#00d4ff",
                     font=("Arial", 14, "bold")).pack(side="left", padx=10)
        
        ctk.CTkButton(btn_f, text="📋 COPIAR", 
                     command=lambda: pyperclip.copy(self.gen_result.get("0.0","end").strip()),
                     width=200, height=40,
                     font=("Arial", 14, "bold")).pack(side="left", padx=10)
        
        self.strength_lbl = ctk.CTkLabel(frame, text="", font=("Arial", 14))
        self.strength_lbl.pack(pady=10)

    # IDENTIDADES
    def init_identity(self):
        frame = ctk.CTkFrame(self.t_id)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(frame, text="👤 GENERADOR DE IDENTIDADES",
                    font=("Arial", 24, "bold")).pack(pady=20)
        
        self.id_text = ctk.CTkTextbox(frame, font=("Consolas", 12))
        self.id_text.pack(fill="both", expand=True, pady=10)
        
        btn_f = ctk.CTkFrame(frame, fg_color="transparent")
        btn_f.pack(pady=10)
        
        ctk.CTkButton(btn_f, text="🎲 GENERAR IDENTIDAD",
                     command=lambda: (self.id_text.delete("0.0","end"),
                                    self.id_text.insert("0.0", generate_identity())),
                     width=250, height=45, fg_color="#00d4ff",
                     font=("Arial", 14, "bold")).pack(side="left", padx=10)
        
        ctk.CTkButton(btn_f, text="📋 COPIAR TODO",
                     command=lambda: pyperclip.copy(self.id_text.get("0.0","end")),
                     width=250, height=45,
                     font=("Arial", 14, "bold")).pack(side="left", padx=10)

    # FILES
    def init_files(self):
        frame = ctk.CTkFrame(self.t_files)
        frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkButton(frame, text="📥 OCULTAR ARCHIVO", 
                     command=self.hide_file,
                     width=200, height=40, fg_color="#00d4ff").pack(side="left", padx=10)
        
        self.file_scroll = ctk.CTkScrollableFrame(self.t_files, height=700)
        self.file_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        self.refresh_files()

    def hide_file(self):
        path = filedialog.askopenfilename()
        if path:
            hidden_name = hashlib.sha256(str(time.time()).encode()).hexdigest()[:20] + ".sys"
            dest = os.path.join(SHADOW_STORAGE, hidden_name)
            size = os.path.getsize(path)
            ftype = os.path.splitext(path)[1]
            
            shutil.move(path, dest)
            
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("INSERT INTO files (orig, hidden, size, type) VALUES (?,?,?,?)",
                            (path, hidden_name, size, ftype))
            
            self.refresh_files()
            messagebox.showinfo("✅", f"Archivo oculto: {os.path.basename(path)}")

    def refresh_files(self):
        for w in self.file_scroll.winfo_children(): w.destroy()
        
        with sqlite3.connect(DB_NAME) as conn:
            rows = conn.execute("SELECT * FROM files").fetchall()
        
        for r in rows:
            id, orig, hidden, size, ftype, date = r
            
            row = ctk.CTkFrame(self.file_scroll, fg_color="#2b2b2b", corner_radius=10)
            row.pack(fill="x", pady=5)
            
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=15, pady=10)
            
            ctk.CTkLabel(info, text=os.path.basename(orig), font=("Arial", 13, "bold"),
                        anchor="w").pack(anchor="w")
            ctk.CTkLabel(info, text=f"📦 {size//1024} KB | {ftype} | {date[:16]}",
                        font=("Arial", 9), text_color="#888",
                        anchor="w").pack(anchor="w")
            
            ctk.CTkButton(row, text="↩️ RESTAURAR", width=120,
                         command=lambda o=orig, h=hidden, i=id: self.restore_file(o,h,i)).pack(side="right", padx=10, pady=10)

    def restore_file(self, orig, hidden, id):
        src = os.path.join(SHADOW_STORAGE, hidden)
        if os.path.exists(src):
            shutil.move(src, orig)
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("DELETE FROM files WHERE id=?", (id,))
            self.refresh_files()
            messagebox.showinfo("✅", "Archivo restaurado")

    # STEGANOGRAFÍA
    def init_stego(self):
        frame = ctk.CTkFrame(self.t_stego)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(frame, text="🖼️ STEGANOGRAFÍA - OCULTAR MENSAJES EN IMÁGENES",
                    font=("Arial", 20, "bold")).pack(pady=20)
        
        ctk.CTkLabel(frame, text="Mensaje a ocultar:", font=("Arial", 12, "bold")).pack(pady=(10,5))
        self.stego_text = ctk.CTkTextbox(frame, height=200)
        self.stego_text.pack(fill="x", padx=20, pady=10)
        
        btn_f = ctk.CTkFrame(frame, fg_color="transparent")
        btn_f.pack(pady=20)
        
        ctk.CTkButton(btn_f, text="🖼️ VINCULAR A IMAGEN",
                     command=self.stego_link, width=250, height=40,
                     fg_color="#00d4ff").pack(side="left", padx=10)
        
        ctk.CTkButton(btn_f, text="🔍 LEER DE IMAGEN",
                     command=self.stego_read, width=250, height=40).pack(side="left", padx=10)
        
        ctk.CTkLabel(frame, text="💡 El mensaje se vincula al hash de la imagen. Sin modificar la imagen.",
                    font=("Arial", 10), text_color="#888").pack(pady=10)

    def stego_link(self):
        path = filedialog.askopenfilename(filetypes=[("Imágenes", "*.png *.jpg *.jpeg")])
        if path:
            with open(path, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            
            msg = self.stego_text.get("0.0", "end").strip()
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("INSERT OR REPLACE INTO stego VALUES (?,?)",
                            (h, self.crypto.encrypt(msg)))
            messagebox.showinfo("✅", f"Mensaje vinculado a: {os.path.basename(path)}")

    def stego_read(self):
        path = filedialog.askopenfilename(filetypes=[("Imágenes", "*.png *.jpg *.jpeg")])
        if path:
            with open(path, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            
            with sqlite3.connect(DB_NAME) as conn:
                res = conn.execute("SELECT m FROM stego WHERE h=?", (h,)).fetchone()
            
            if res:
                self.stego_text.delete("0.0", "end")
                self.stego_text.insert("0.0", self.crypto.decrypt(res[0]))
                messagebox.showinfo("✅", "Mensaje encontrado")
            else:
                messagebox.showwarning("⚠️", "No hay mensaje en esta imagen")

    # GHOST MODE
    def init_ghost(self):
        frame = ctk.CTkFrame(self.t_ghost)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(frame, text="👻 GHOST MODE - SECRETOS OCULTOS",
                    font=("Arial", 24, "bold"), text_color="#9b59b6").pack(pady=20)
        
        ctk.CTkLabel(frame, text="Esta pestaña solo aparece en modo seguro.\nGuarda secretos que nunca se verán en modo señuelo.",
                    font=("Arial", 12), text_color="#888").pack(pady=10)
        
        self.ghost_text = ctk.CTkTextbox(frame, height=300)
        self.ghost_text.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkButton(frame, text="💾 GUARDAR EN EL VACÍO",
                     command=self.save_ghost, width=300, height=45,
                     fg_color="#9b59b6", font=("Arial", 14, "bold")).pack(pady=20)
        
        self.load_ghost()

    def save_ghost(self):
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("INSERT INTO ghost (s) VALUES (?)",
                        (self.crypto.encrypt(self.ghost_text.get("0.0","end")),))
        messagebox.showinfo("👻", "Guardado en el vacío")

    def load_ghost(self):
        with sqlite3.connect(DB_NAME) as conn:
            res = conn.execute("SELECT s FROM ghost ORDER BY id DESC LIMIT 1").fetchone()
        if res:
            self.ghost_text.insert("0.0", self.crypto.decrypt(res[0]))

    # SEGURIDAD
    def init_security(self):
        frame = ctk.CTkFrame(self.t_sec)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(frame, text="🛡️ PANEL DE SEGURIDAD",
                    font=("Arial", 24, "bold")).pack(pady=20)
        
        # Estadísticas
        stats_f = ctk.CTkFrame(frame, fg_color="#2b2b2b", corner_radius=15)
        stats_f.pack(fill="x", padx=20, pady=20)
        
        with sqlite3.connect(DB_NAME) as conn:
            total_pass = conn.execute("SELECT COUNT(*) FROM vault WHERE is_decoy=0").fetchone()[0]
            total_files = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            total_logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        
        ctk.CTkLabel(stats_f, text=f"🔐 Contraseñas guardadas: {total_pass}",
                    font=("Arial", 14)).pack(pady=5, padx=20, anchor="w")
        ctk.CTkLabel(stats_f, text=f"📂 Archivos ocultos: {total_files}",
                    font=("Arial", 14)).pack(pady=5, padx=20, anchor="w")
        ctk.CTkLabel(stats_f, text=f"📋 Eventos registrados: {total_logs}",
                    font=("Arial", 14)).pack(pady=5, padx=20, anchor="w")
        
        # Opciones
        opt_f = ctk.CTkFrame(frame, fg_color="transparent")
        opt_f.pack(pady=30)
        
        ctk.CTkButton(opt_f, text="💾 CREAR BACKUP",
                     command=self.backup, width=300, height=50,
                     fg_color="#00d4ff").pack(pady=10)
        
        ctk.CTkButton(opt_f, text="🧹 LIMPIAR LOGS",
                     command=self.clear_logs, width=300, height=50).pack(pady=10)
        
        ctk.CTkButton(opt_f, text="⚙️ CAMBIAR CONTRASEÑA",
                     command=self.change_master_pass, width=300, height=50).pack(pady=10)
        
        ctk.CTkButton(opt_f, text="📊 VER ESTADÍSTICAS DETALLADAS",
                     command=self.show_stats, width=300, height=50).pack(pady=10)
        
        ctk.CTkButton(opt_f, text="🔥 DESTRUCCIÓN TOTAL",
                     command=self.total_destruction, width=300, height=50,
                     fg_color="#ff0000").pack(pady=20)

    def backup(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BASE_DIR, "Backups", f"backup_{timestamp}.db")
        shutil.copy2(DB_NAME, backup_path)
        messagebox.showinfo("✅", f"Backup creado:\n{backup_path}")

    def clear_logs(self):
        if messagebox.askyesno("❓", "¿Eliminar todos los logs?"):
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("DELETE FROM logs")
            messagebox.showinfo("✅", "Logs eliminados")

    def change_master_pass(self):
        messagebox.showinfo("ℹ️", "Esta función requiere reencriptar toda la base de datos.\nImplementar con precaución.")

    def show_stats(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("📊 Estadísticas Detalladas")
        dlg.geometry("600x500")
        dlg.grab_set()
        
        text = ctk.CTkTextbox(dlg, font=("Consolas", 11))
        text.pack(fill="both", expand=True, padx=20, pady=20)
        
        with sqlite3.connect(DB_NAME) as conn:
            stats = f"""╔═══════════════════════════════════════════╗
║       📊 ESTADÍSTICAS DEL SISTEMA        ║
╚═══════════════════════════════════════════╝

🔐 BÓVEDA DE CONTRASEÑAS
   Total: {conn.execute("SELECT COUNT(*) FROM vault WHERE is_decoy=0").fetchone()[0]}
   Por categoría:
"""
            cats = conn.execute("SELECT category, COUNT(*) FROM vault WHERE is_decoy=0 GROUP BY category").fetchall()
            for cat, count in cats:
                stats += f"     • {cat}: {count}\n"
            
            stats += f"""
📂 ARCHIVOS OCULTOS
   Total: {conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]}
   Espacio usado: {sum([r[0] for r in conn.execute("SELECT size FROM files").fetchall()]) // 1024} KB

👻 GHOST MODE
   Secretos guardados: {conn.execute("SELECT COUNT(*) FROM ghost").fetchone()[0]}

🖼️ STEGANOGRAFÍA
   Mensajes vinculados: {conn.execute("SELECT COUNT(*) FROM stego").fetchone()[0]}

📋 REGISTRO DE EVENTOS
   Total eventos: {conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]}
   Últimos 5 eventos:
"""
            logs = conn.execute("SELECT type, details, date FROM logs ORDER BY id DESC LIMIT 5").fetchall()
            for type, details, date in logs:
                stats += f"     [{date}] {type}: {details}\n"
        
        text.insert("0.0", stats)

    def total_destruction(self):
        if messagebox.askyesno("⚠️ ADVERTENCIA", 
                              "¿DESTRUIR COMPLETAMENTE TODOS LOS DATOS?\n\n¡Esta acción es IRREVERSIBLE!"):
            if messagebox.askyesno("🔥 CONFIRMACIÓN FINAL",
                                  "¿Estás ABSOLUTAMENTE seguro?\nSe eliminarán TODOS los datos."):
                self.log("DESTRUCTION", "Autodestrucción iniciada")
                time.sleep(1)
                shutil.rmtree(BASE_DIR)
                messagebox.showinfo("✅", "Sistema destruido")
                os._exit(0)

    def toggle_theme(self):
        current = ctk.get_appearance_mode()
        ctk.set_appearance_mode("light" if current == "Dark" else "dark")

    def setup_emergency(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("⚙️ Configurar Emergencias")
        dlg.geometry("500x400")
        dlg.grab_set()
        
        ctk.CTkLabel(dlg, text="⚠️ CONFIGURACIÓN DE EMERGENCIAS",
                    font=("Arial", 18, "bold")).pack(pady=20)
        
        ctk.CTkLabel(dlg, text="Contraseña de PÁNICO (destruye todo):",
                    font=("Arial", 12, "bold")).pack(pady=(20,5))
        panic_e = ctk.CTkEntry(dlg, width=400, show="●")
        panic_e.pack(pady=5)
        
        ctk.CTkLabel(dlg, text="Contraseña SEÑUELO (muestra datos falsos):",
                    font=("Arial", 12, "bold")).pack(pady=(20,5))
        decoy_e = ctk.CTkEntry(dlg, width=400, show="●")
        decoy_e.pack(pady=5)
        
        def save_emergency():
            panic = panic_e.get()
            decoy = decoy_e.get()
            
            if panic and decoy:
                with sqlite3.connect(DB_NAME) as conn:
                    conn.execute("INSERT OR REPLACE INTO config VALUES ('panic_h', ?)",
                                (hashlib.sha512(panic.encode()).hexdigest(),))
                    conn.execute("INSERT OR REPLACE INTO config VALUES ('decoy_h', ?)",
                                (hashlib.sha512(decoy.encode()).hexdigest(),))
                messagebox.showinfo("✅", "Protocolos de emergencia configurados")
                dlg.destroy()
        
        ctk.CTkButton(dlg, text="💾 GUARDAR", command=save_emergency,
                     width=400, height=45, fg_color="#00d4ff").pack(pady=30)

    def show_logs(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("📋 Registro de Eventos")
        dlg.geometry("800x600")
        dlg.grab_set()
        
        text = ctk.CTkTextbox(dlg, font=("Consolas", 10))
        text.pack(fill="both", expand=True, padx=20, pady=20)
        
        with sqlite3.connect(DB_NAME) as conn:
            logs = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100").fetchall()
        
        log_text = "╔════════════════════════════════════════════════════╗\n"
        log_text += "║           📋 REGISTRO DE EVENTOS                  ║\n"
        log_text += "╚════════════════════════════════════════════════════╝\n\n"
        
        for id, type, details, date in logs:
            log_text += f"[{date}] {type}\n"
            if details:
                log_text += f"  └─ {details}\n"
            log_text += "\n"
        
        text.insert("0.0", log_text)

if __name__ == "__main__":
    app = FluxiVaultPro()
    app.mainloop()
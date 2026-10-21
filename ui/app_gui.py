import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from core.exceptions import SecurityAuditException
from controllers.app_controller import SecurityAppController


class SecurityAuditGUI:
  """Interfaz Grafica de Usuario (GUI) orientada a objetos para el auditor."""

  def __init__(self, root: tk.Tk):
    self._root = root
    self._root.title("Suite de Auditoria de Seguridad y Monitor de Red")
    self._root.geometry("880x580")
    self._controller = SecurityAppController()

    self._crear_widgets()

  def _crear_widgets(self):
    self._tabs = ttk.Notebook(self._root)
    self._tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Pestana 1: Red y Puertos
    self._tab_red = ttk.Frame(self._tabs)
    self._tabs.add(self._tab_red, text="Puertos y Conexiones")
    self._configurar_tab_red()

    # Pestana 2: Threat Intelligence
    self._tab_threat = ttk.Frame(self._tabs)
    self._tabs.add(self._tab_threat, text="Threat Intelligence (CVEs)")
    self._configurar_tab_threat()

    # Pestana 3: Procesos y Mitigacion
    self._tab_procesos = ttk.Frame(self._tabs)
    self._tabs.add(self._tab_procesos, text="Procesos y Mitigacion")
    self._configurar_tab_procesos()

  def _configurar_tab_red(self):
    btn_frame = ttk.Frame(self._tab_red)
    btn_frame.pack(fill=tk.X, padx=5, pady=5)

    btn_escanear = ttk.Button(btn_frame, text="Escanear Puertos Locales", command=self._on_escanear_puertos)
    btn_escanear.pack(side=tk.LEFT, padx=5)

    columnas = ("proto", "puerto", "servicio", "pid", "proceso", "ip")
    self._tabla_puertos = ttk.Treeview(self._tab_red, columns=columnas, show="headings")
    for col in columnas:
      self._tabla_puertos.heading(col, text=col.upper())
      self._tabla_puertos.column(col, width=130, anchor=tk.CENTER)

    self._tabla_puertos.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

  def _configurar_tab_threat(self):
    search_frame = ttk.Frame(self._tab_threat)
    search_frame.pack(fill=tk.X, padx=5, pady=5)

    ttk.Label(search_frame, text="Servicio / Software:").pack(side=tk.LEFT, padx=5)
    self._entry_servicio = ttk.Entry(search_frame, width=25)
    self._entry_servicio.pack(side=tk.LEFT, padx=5)

    btn_buscar = ttk.Button(search_frame, text="Consultar CVEs", command=self._on_consultar_cves)
    btn_buscar.pack(side=tk.LEFT, padx=5)

    columnas = ("cve", "cvss", "severidad", "descripcion")
    self._tabla_cves = ttk.Treeview(self._tab_threat, columns=columnas, show="headings")
    self._tabla_cves.heading("cve", text="CVE ID")
    self._tabla_cves.heading("cvss", text="CVSS")
    self._tabla_cves.heading("severidad", text="SEVERIDAD")
    self._tabla_cves.heading("descripcion", text="DESCRIPCION")
    self._tabla_cves.column("cve", width=140)
    self._tabla_cves.column("cvss", width=70, anchor=tk.CENTER)
    self._tabla_cves.column("severidad", width=100, anchor=tk.CENTER)
    self._tabla_cves.column("descripcion", width=520)

    self._tabla_cves.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

  def _configurar_tab_procesos(self):
    btn_frame = ttk.Frame(self._tab_procesos)
    btn_frame.pack(fill=tk.X, padx=5, pady=5)

    btn_escanear = ttk.Button(btn_frame, text="Auditar Procesos", command=self._on_escanear_procesos)
    btn_escanear.pack(side=tk.LEFT, padx=5)

    btn_mitigar = ttk.Button(btn_frame, text="Mitigar Amenaza (Kill PID)", command=self._on_mitigar_proceso)
    btn_mitigar.pack(side=tk.LEFT, padx=5)

    columnas = ("pid", "nombre", "cpu", "mem", "sospechoso", "ruta")
    self._tabla_procesos = ttk.Treeview(self._tab_procesos, columns=columnas, show="headings")
    for col in columnas:
      self._tabla_procesos.heading(col, text=col.upper())
      self._tabla_procesos.column(col, width=120, anchor=tk.CENTER)

    self._tabla_procesos.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

  def _on_escanear_puertos(self):
    self._tabla_puertos.delete(*self._tabla_puertos.get_children())
    try:
      puertos = self._controller.ejecutar_auditoria_red()
      for p in puertos:
        self._tabla_puertos.insert(
          "",
          tk.END,
          values=(p.protocolo, p.numero, p.servicio_estimado, p.pid or "N/A", p.proceso, p.ip_origen)
        )
    except Exception as e:
      messagebox.showerror("Error de Auditoria", f"No se pudo completar el escaneo: {str(e)}")

  def _on_consultar_cves(self):
    servicio = self._entry_servicio.get().strip()
    if not servicio:
      messagebox.showwarning("Atencion", "Ingrese el nombre del servicio (ej. ssh, curl, http)")
      return

    self._tabla_cves.delete(*self._tabla_cves.get_children())
    try:
      cves = self._controller.consultar_cves(servicio)
      if not cves:
        messagebox.showinfo("Sin Hallazgos", f"No se encontraron CVEs para '{servicio}'.")
        return

      for c in cves:
        self._tabla_cves.insert("", tk.END, values=(c.cve_id, c.puntaje_cvss, c.severidad, c.descripcion))
    except Exception as e:
      messagebox.showerror("Fallo de API", f"Error consultando base de amenazas: {str(e)}")

  def _on_escanear_procesos(self):
    self._tabla_procesos.delete(*self._tabla_procesos.get_children())
    try:
      procesos = self._controller.ejecutar_auditoria_procesos()
      for proc in procesos:
        alerta = "SI (!)" if proc.es_sospechoso else "NO"
        self._tabla_procesos.insert(
          "",
          tk.END,
          values=(proc.pid, proc.nombre, f"{proc.uso_cpu}%", f"{proc.uso_memoria_mb} MB", alerta, proc.ruta_ejecutable)
        )
    except Exception as e:
      messagebox.showerror("Error", f"Fallo al auditar procesos: {str(e)}")

  def _on_mitigar_proceso(self):
    pid_str = simpledialog.askstring("Mitigacion de Amenaza", "Ingrese el PID del proceso a finalizar:")
    if not pid_str:
      return

    try:
      pid = int(pid_str)
      confirm = messagebox.askyesno(
        "Confirmar Mitigacion", f"Esta seguro de enviar senal de terminacion al PID {pid}?"
      )
      if confirm:
        self._controller.mitigar_proceso(pid)
        messagebox.showinfo("Exito", f"El proceso con PID {pid} fue finalizado correctamente.")
        self._on_escanear_procesos()
    except ValueError:
      messagebox.showerror("Error de Formato", "El PID ingresado debe ser un numero entero.")
    except SecurityAuditException as sae:
      messagebox.showerror("Excepcion de Mitigacion", sae.mensaje)
    except Exception as e:
      messagebox.showerror("Error Inesperado", f"Ocurrio un fallo imprevisto: {str(e)}")
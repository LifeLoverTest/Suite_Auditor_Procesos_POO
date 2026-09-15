import sys
from Puerto_Service import AuditorPuertos
from proyecto import ThreatIntelligence

def renderizar_encabezado():
  print("\n" + "=" * 75)
  print("        SUITE DE AUDITORIA DE SEGURIDAD LOCAL Y THREAT INTEL (CLI)        ")
  print("=" * 75)

def ejecutar_auditoria_puertos():
  auditor = AuditorPuertos()
  
  print("\n[*] Inspeccionando sockets locales en modo escucha (LISTEN)...")
  puertos = auditor.obtener_puertos_en_escucha()

  if not puertos:
    print("[-] No se detectaron puertos en modo escucha o sockets activos.")
    return

  print(f"[+] Se identificaron {len(puertos)} sockets activos en el host.")
  print("-" * 75)
  print(f"{'PROTO':<6} | {'PUERTO':<7} | {'SERVICIO':<15} | {'PID':<8} | {'PROCESO':<25}")
  print("-" * 75)

  for p in puertos:
    print(f"{p.protocolo.upper():<6} | {p.numero:<7} | {p.servicio_estimado:<15} | {p.pid:<8} | {p.proceso:<25}")

  print("-" * 75)

def consultar_vulnerabilidades_servicio():
  intel = ThreatIntelligence()
  
  print("\n[*] MODULO DE INTELIGENCIA DE AMENAZAS (THREAT INTEL)")
  servicio = input("[?] Ingrese el nombre del servicio a consultar (ej. http, ssh, ntp): ").strip().lower()

  if not servicio:
    print("[!] No ingreso ningun servicio. Operacion cancelada.")
    return

  print(f"\n[*] Consultando reportes CVE y base de datos CIRCL para '{servicio}'...")
  vulnerabilidades = intel.consultar_vulnerabilidades_servicio(servicio, limite=5)

  if not vulnerabilidades:
    print(f"[-] No se registraron vulnerabilidades para el servicio '{servicio}'.")
    return

  print(f"\n[!] Reportes de seguridad encontrados ({len(vulnerabilidades)}):")
  print("-" * 75)
  for v in vulnerabilidades:
    print(f"ID CVE    : {v.cve_id}")
    print(f"Severidad : {v.severidad} (Puntaje CVSS: {v.puntaje_cvss})")
    print(f"Resumen   : {v.descripcion}")
    print("-" * 75)

def menu_principal():
  while True:
    renderizar_encabezado()
    print("1. Auditar puertos locales y procesos en escucha")
    print("2. Consultar vulnerabilidades (Threat Intelligence) por servicio")
    print("3. Salir")
    print("-" * 75)

    opcion = input("Seleccione una opcion [1-3]: ").strip()

    if opcion == "1":
      ejecutar_auditoria_puertos()
    elif opcion == "2":
      consultar_vulnerabilidades_servicio()
    elif opcion == "3":
      print("\n[+] Saliendo de la Suite de Auditoria...")
      sys.exit(0)
    else:
      print("\n[!] Opcion invalida. Ingrese un numero del 1 al 3.")

if __name__ == "__main__":
  menu_principal()
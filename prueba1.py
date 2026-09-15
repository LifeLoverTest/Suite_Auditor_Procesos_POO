from proyecto import ThreatIntelligence

intel = ThreatIntelligence()

servicio = "curl"
print(f"[*] Consultando API en vivo para '{servicio}'...")
resultados = intel.consultar_vulnerabilidades_servicio(servicio, limite=2)

print(f"\n[+] Resultados obtenidos: {len(resultados)}")
for v in resultados:
  print(f" -> ID: {v.cve_id} | Score: {v.puntaje_cvss} | Severidad: {v.severidad}")
  print(f"    Descripcion: {v.descripcion}\n")
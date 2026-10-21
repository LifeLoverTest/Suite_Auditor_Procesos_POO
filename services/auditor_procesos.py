from typing import List
import psutil
from core.models import ProcesoAuditable


class AuditorProcesos:
  """Servicio encargado de monitorear hardware y evaluar heuristica de procesos."""

  def _es_ruta_sospechosa(self, ruta: str) -> bool:
    """Evalua si el ejecutable reside en directorios temporales vulnerables."""
    if not ruta or ruta == "N/A":
      return False
    r = ruta.lower()
    directorios_riesgo = ["appdata\\local\\temp", "\\temp\\", "appdata\\roaming", "/tmp"]
    return any(p in r for p in directorios_riesgo)

  def escanear_procesos(self, limite: int = 50) -> List[ProcesoAuditable]:
    """Itera la tabla de procesos extrayendo CPU, memoria RSS y estado heuristico."""
    procesos: List[ProcesoAuditable] = []

    for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_info"]):
      try:
        info = proc.info
        pid = info["pid"]
        nombre = info["name"] or "Desconocido"
        ruta = info["exe"] or "N/A"
        cpu = info["cpu_percent"] or 0.0

        mem_mb = 0.0
        if info["memory_info"]:
          mem_mb = info["memory_info"].rss / (1024 * 1024)

        sospechoso = self._es_ruta_sospechosa(ruta)

        procesos.append(
          ProcesoAuditable(
            pid=pid,
            nombre=nombre,
            ruta_ejecutable=ruta,
            uso_cpu=round(cpu, 2),
            uso_memoria_mb=round(mem_mb, 2),
            es_sospechoso=sospechoso
          )
        )
      except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        continue

      if len(procesos) >= limite:
        break

    return procesos
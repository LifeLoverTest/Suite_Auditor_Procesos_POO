from typing import List
from core.models import ProcesoAuditable, PuertoActivo, Vulnerabilidad
from services.auditor_procesos import AuditorProcesos
from services.auditor_puertos import AuditorPuertos
from services.mitigador import MitigadorAmenazas
from services.threat_intel import ThreatIntelligence


class SecurityAppController:
  """Controlador mediador que desacopla la vista de los servicios del sistema."""

  def __init__(self):
    self._auditor_puertos = AuditorPuertos()
    self._threat_intel = ThreatIntelligence()
    self._auditor_procesos = AuditorProcesos()
    self._mitigador = MitigadorAmenazas()

  def ejecutar_auditoria_red(self) -> List[PuertoActivo]:
    return self._auditor_puertos.obtener_puertos_en_escucha()

  def consultar_cves(self, servicio: str, limite: int = 3) -> List[Vulnerabilidad]:
    return self._threat_intel.consultar_vulnerabilidades_servicio(servicio, limite=limite)

  def ejecutar_auditoria_procesos(self, limite: int = 50) -> List[ProcesoAuditable]:
    return self._auditor_procesos.escanear_procesos(limite=limite)

  def mitigar_proceso(self, pid: int) -> bool:
    return self._mitigador.terminar_proceso(pid)
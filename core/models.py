from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Vulnerabilidad:
  """Entidad inmutable que representa un fallo CVE reportado."""
  cve_id: str
  descripcion: str
  puntaje_cvss: float
  severidad: str

  def es_critica(self) -> bool:
    return self.puntaje_cvss >= 9.0


@dataclass
class PuertoActivo:
  """Entidad que modela un socket local activo en el sistema."""
  numero: int
  protocolo: str
  ip_origen: str
  pid: Optional[int]
  proceso: str
  servicio_estimado: str
  estado: str
  vulnerabilidades: List[Vulnerabilidad] = field(default_factory=list)

  def agregar_vulnerabilidad(self, vuln: Vulnerabilidad) -> None:
    self.vulnerabilidades.append(vuln)

  def tiene_vulnerabilidades(self) -> bool:
    return len(self.vulnerabilidades) > 0


@dataclass(frozen=True)
class ProcesoAuditable:
  """Entidad inmutable que almacena metricas de ejecucion y heuristica."""
  pid: int
  nombre: str
  ruta_ejecutable: str
  uso_cpu: float
  uso_memoria_mb: float
  es_sospechoso: bool

  def evaluar_heuristica(self) -> bool:
    return self.es_sospechoso
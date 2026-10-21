from typing import List
import requests
from core.exceptions import ApiThreatException
from core.models import Vulnerabilidad


class ThreatIntelligence:
  """Servicio encargado de correlacionar servicios con vulnerabilidades (CVEs)."""

  def __init__(self, timeout: int = 8):
    self._timeout = timeout
    self._headers = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditSuite/2.0"
    }
    self._cve_fallback = {
      "ssh": [
        Vulnerabilidad("CVE-2024-6387", "RegreSSHion: Condicion de carrera en senales de OpenSSH.", 9.8, "CRITICA"),
        Vulnerabilidad("CVE-2023-38408", "Posible ejecucion remota de codigo en ssh-agent PKCS#11.", 8.1, "ALTA")
      ],
      "http": [
        Vulnerabilidad("CVE-2021-41773", "Path traversal y ejecucion de codigo en servidor HTTP.", 9.8, "CRITICA"),
        Vulnerabilidad("CVE-2023-44487", "Ataque HTTP/2 Rapid Reset que causa denegacion de servicio.", 7.5, "ALTA")
      ],
      "curl": [
        Vulnerabilidad("CVE-2023-38545", "Desbordamiento de buffer en protocolo SOCKS5 en libcurl.", 9.8, "CRITICA"),
        Vulnerabilidad("CVE-2023-38546", "Inyeccion de cookies en conexiones simultaneas con libcurl.", 3.7, "BAJA")
      ],
      "ntp": [
        Vulnerabilidad("CVE-2016-7434", "Fallo DoS mediante paquetes mrulist especialmente diseñados.", 7.5, "ALTA")
      ],
      "epmap": [
        Vulnerabilidad("CVE-2022-26809", "Vulnerabilidad RPC con posible ejecucion remota de codigo.", 9.8, "CRITICA")
      ]
    }

  def _determinar_severidad(self, cvss: float) -> str:
    """Clasifica la severidad segun el estandar CVSS v3."""
    if cvss >= 9.0:
      return "CRITICA"
    elif cvss >= 7.0:
      return "ALTA"
    elif cvss >= 4.0:
      return "MEDIA"
    elif cvss > 0.0:
      return "BAJA"
    return "DESCONOCIDA"

  def activar_fallback(self, servicio: str, limite: int = 2) -> List[Vulnerabilidad]:
    """Retorna registros de la base local de respaldo."""
    serv = servicio.lower().strip()
    clave = "ssh" if "ssh" in serv else ("http" if "http" in serv else ("curl" if "curl" in serv else serv))
    if clave in self._cve_fallback:
      return self._cve_fallback[clave][:limite]
    return []

  def consultar_vulnerabilidades_servicio(self, nombre_servicio: str, limite: int = 2) -> List[Vulnerabilidad]:
    """Consulta CVEs en la API publica de NVD/NIST o recurre al fallback local."""
    servicio_limpio = nombre_servicio.lower().strip()
    if not servicio_limpio or servicio_limpio in ["desconocido", "n/a", "acceso restringido", "sistema / protegido"]:
      return []

    vulnerabilidades: List[Vulnerabilidad] = []
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={servicio_limpio}&resultsPerPage={limite}"

    try:
      respuesta = requests.get(url, headers=self._headers, timeout=self._timeout)

      if respuesta.status_code != 200:
        raise ApiThreatException(respuesta.status_code)

      datos = respuesta.json()
      items = datos.get("vulnerabilities", [])

      for item in items:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "CVE-DESCONOCIDO")

        resumen = "Sin descripcion disponible"
        for d in cve_data.get("descriptions", []):
          if d.get("lang") == "en":
            resumen = d.get("value", resumen)
            break

        cvss_score = 7.0
        metrics = cve_data.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        if cvss_v3:
          cvss_score = float(cvss_v3[0].get("cvssData", {}).get("baseScore", 7.0))

        vulnerabilidades.append(
          Vulnerabilidad(
            cve_id=cve_id,
            descripcion=resumen[:110] + "..." if len(resumen) > 110 else resumen,
            puntaje_cvss=cvss_score,
            severidad=self._determinar_severidad(cvss_score)
          )
        )

    except (requests.exceptions.RequestException, ApiThreatException):
      return self.activar_fallback(servicio_limpio, limite)

    return vulnerabilidades if vulnerabilidades else self.activar_fallback(servicio_limpio, limite)
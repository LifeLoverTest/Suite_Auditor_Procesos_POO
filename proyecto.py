from typing import List
import requests
from models import Vulnerabilidad


class ThreatIntelligence:
  """
  Servicio encargado de correlacionar servicios de red con vulnerabilidades publicadas (CVEs).
  Cumple con el RF02 (Requisito Innovador 1).
  """

  def __init__(self, timeout: int = 6):
    self._timeout = timeout
    self._headers = {
      "User-Agent": "SecurityAuditSuite/1.0 (Academic-Research-Client)"
    }
    # Base de conocimientos local de contingencia (fallback offline/resiliencia)
    self._cve_fallback = {
      "ssh": [
        Vulnerabilidad("CVE-2023-38408", "Posible ejecucion remota de codigo en ssh-agent PKCS#11.", 8.1, "ALTA"),
        Vulnerabilidad("CVE-2024-6387", "RegreSSHion: Condicion de carrera de senales en OpenSSH.", 9.8, "CRITICA")
      ],
      "http": [
        Vulnerabilidad("CVE-2021-41773", "Path traversal y ejecucion de codigo en Apache HTTP Server 2.4.49.", 9.8, "CRITICA"),
        Vulnerabilidad("CVE-2023-44487", "Ataque HTTP/2 Rapid Reset que causa denegacion de servicio.", 7.5, "ALTA")
      ],
      "ntp": [
        Vulnerabilidad("CVE-2016-7434", "Fallo de denegacion de servicio mediante paquetes mrulist especialmente diseñados.", 7.5, "ALTA"),
        Vulnerabilidad("CVE-2015-7704", "Vulnerabilidad de saturacion y alteracion de tiempo (Kiss-o'-Death).", 7.5, "ALTA")
      ],
      "epmap": [
        Vulnerabilidad("CVE-2022-26809", "Vulnerabilidad de ejecucion remota de codigo en llamadas a procedimiento remoto (RPC).", 9.8, "CRITICA")
      ],
      "netbios-ns": [
        Vulnerabilidad("CVE-2020-0796", "SMBGhost: Ejecucion remota de codigo en el controlador srv2.sys de Windows.", 10.0, "CRITICA")
      ]
    }
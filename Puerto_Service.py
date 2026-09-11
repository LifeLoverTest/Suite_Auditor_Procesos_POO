from dataclasses import dataclass
from typing import List, Optional
import socket
import psutil


@dataclass(frozen=True)
class PuertoActivo:
  """
  Entidad inmutable que representa un puerto en uso en el sistema.
  """
  numero: int
  protocolo: str
  ip_origen: str
  pid: Optional[int]
  proceso: str
  servicio_estimado: str
  estado: str


class AuditorPuertos:
  """
  Servicio encargado de auditar la red local y los sockets en escucha del SO.
  Aplica SRP (Single Responsibility Principle) encapsulando el uso de psutil y socket.
  """

  def __init__(self, tipo_red: str = "inet"):
    # 'inet' filtra conexiones IPv4 e IPv6
    self._tipo_red = tipo_red
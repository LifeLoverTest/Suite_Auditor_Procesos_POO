import socket
from typing import List
import psutil
from core.models import PuertoActivo


class AuditorPuertos:
  """Servicio encargado de auditar la red local y sockets en escucha del SO."""

  def __init__(self, tipo_red: str = "inet"):
    self._tipo_red = tipo_red

  def resolver_servicio(self, puerto: int, protocolo: str) -> str:
    """Traduce el numero de puerto a nombre estandar IANA."""
    try:
      return socket.getservbyport(puerto, protocolo.lower())
    except (OSError, socket.error):
      return "Desconocido"

  def obtener_puertos_en_escucha(self) -> List[PuertoActivo]:
    """Inspecciona el sistema y extrae sockets en LISTEN o UDP activos."""
    puertos_encontrados: List[PuertoActivo] = []

    try:
      conexiones = psutil.net_connections(kind=self._tipo_red)
    except psutil.AccessDenied:
      conexiones = []

    for conn in conexiones:
      if conn.status == psutil.CONN_LISTEN or (conn.type == socket.SOCK_DGRAM and conn.laddr):
        num_puerto = conn.laddr.port
        ip_local = conn.laddr.ip
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        pid = conn.pid
        nombre_proceso = "Sistema / Protegido"

        if pid:
          try:
            proceso_obj = psutil.Process(pid)
            nombre_proceso = proceso_obj.name()
          except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            nombre_proceso = "Acceso Restringido"

        servicio = self.resolver_servicio(num_puerto, proto)

        puerto_activo = PuertoActivo(
          numero=num_puerto,
          protocolo=proto,
          ip_origen=ip_local,
          pid=pid,
          proceso=nombre_proceso,
          servicio_estimado=servicio,
          estado=conn.status if conn.status else "UDP_ACTIVO"
        )
        puertos_encontrados.append(puerto_activo)

    return self.ordenar_puertos(puertos_encontrados)

  def ordenar_puertos(self, puertos: List[PuertoActivo]) -> List[PuertoActivo]:
    """Ordena ascendentemente por numero de puerto sin mutar la lista original."""
    return sorted(puertos, key=lambda x: x.numero)
class SecurityAuditException(Exception):
  """Excepcion base abstracta para el sistema de auditoria."""
  def __init__(self, mensaje: str):
    super().__init__(mensaje)
    self.mensaje = mensaje


class PermisosInsuficientesError(SecurityAuditException):
  """Lanzada cuando se rechaza una operacion por falta de privilegios de Administrador."""
  def __init__(self, pid: int, mensaje: str = "Acceso denegado. Se requieren permisos de Administrador"):
    super().__init__(f"{mensaje} (PID: {pid})")
    self.pid_afectado = pid


class ProcesoNoEncontradoError(SecurityAuditException):
  """Lanzada cuando el PID solicitado ya no existe en el sistema operativo."""
  def __init__(self, pid: int, mensaje: str = "El proceso no existe o finalizo previamente"):
    super().__init__(f"{mensaje} (PID: {pid})")
    self.pid_afectado = pid


class ApiThreatException(SecurityAuditException):
  """Lanzada cuando la comunicacion con la API externa de amenazas falla."""
  def __init__(self, codigo_estado: int, mensaje: str = "Fallo de respuesta en API de amenazas"):
    super().__init__(f"{mensaje} (HTTP {codigo_estado})")
    self.codigo_estado = codigo_estado
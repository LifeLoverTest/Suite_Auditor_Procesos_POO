import psutil
from core.exceptions import PermisosInsuficientesError, ProcesoNoEncontradoError


class MitigadorAmenazas:
  """Modulo responsable de la respuesta a incidentes y finalizacion de procesos."""

  def terminar_proceso(self, pid: int) -> bool:
    """Finaliza un proceso de forma controlada o forzada segun el estado del proceso."""
    try:
      proc = psutil.Process(pid)
      proc.terminate()
      proc.wait(timeout=2)
      return True
    except psutil.TimeoutExpired:
      proc.kill()
      return True
    except psutil.AccessDenied:
      raise PermisosInsuficientesError(pid)
    except psutil.NoSuchProcess:
      raise ProcesoNoEncontradoError(pid)
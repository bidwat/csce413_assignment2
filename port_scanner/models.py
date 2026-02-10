from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ScanResult:
    target: str
    port: int
    is_open: bool
    elapsed_s: float
    service: Optional[str] = None
    banner: Optional[str] = None

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
import re
from pathlib import Path

BLOCK_RE = re.compile(r'(<[^>]+>\s*a\s*sao:(?:Point|Observation)[\s\S]*?\.)', re.MULTILINE)
TL_AT_RE = re.compile(r'tl:at\s+"([^"]+)"\^\^xsd:dateTime')
SAO_VALUE_PAT = re.compile(r'sao:value\s+"([^"]+)"')
SAO_UNIT_PAT  = re.compile(r'sao:hasUnitOfMeasurement\s+([^\s;]+)')
SENSOR_ID_FROM_IRI = re.compile(r'trafficData(\d+)')


@dataclass(frozen=True)
class DataEvent:
    t: float
    sensor_id: str
    value: Optional[str]
    unit: Optional[str]
    bytes_payload: int
    ttl_file: Optional[str] = None


def _parse_time_iso8601_to_epoch(ts: str) -> float:
    try:
        from datetime import datetime, timezone
        if ts.endswith('Z'):
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        else:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


def parse_ttl_file(path: Path, default_payload_bytes: int = 200) -> List[DataEvent]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    events: List[DataEvent] = []
    file_sensor_id = path.stem
    m_id = SENSOR_ID_FROM_IRI.search(text)
    if m_id:
        file_sensor_id = f"trafficData{m_id.group(1)}"
    current_subject: Optional[str] = None
    last_time: Optional[float] = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('<') and 'a sao:' in line:
            m = re.match(r'(<[^>]+>)', line)
            if m:
                current_subject = m.group(1)
                if SENSOR_ID_FROM_IRI.search(current_subject):
                    mid = SENSOR_ID_FROM_IRI.search(current_subject).group(1)
                    current_subject = f"trafficData{mid}"
                else:
                    current_subject = current_subject[1:-1]
            continue
        mt = TL_AT_RE.search(line)
        if mt:
            last_time = _parse_time_iso8601_to_epoch(mt.group(1))
            continue
        mv = SAO_VALUE_PAT.search(line)
        if mv and last_time is not None:
            val = mv.group(1)
            sid = current_subject or file_sensor_id
            events.append(DataEvent(t=last_time, sensor_id=sid, value=val, unit=None,
                                    bytes_payload=default_payload_bytes, ttl_file=path.name))
            last_time = None
    events.sort(key=lambda e: e.t)
    return events


def parse_ttl_dir(dir_path: Path, default_payload_bytes: int = 200):
    from typing import Dict
    streams: Dict[str, List[DataEvent]] = {}
    for ttl in sorted(dir_path.glob("*.ttl")):
        evs = parse_ttl_file(ttl, default_payload_bytes=default_payload_bytes)
        key = ttl.stem
        streams[key] = [DataEvent(e.t, key, e.value, e.unit, e.bytes_payload, e.ttl_file) for e in evs]
    return streams

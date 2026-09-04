"""Basis fuer passive Paket-Parser."""

from __future__ import annotations

from typing import Iterable, Protocol

from ..store import Observation


class PacketParser(Protocol):
    """Ein Parser pro Protokoll.

    `bpf` wird mit den anderen Parsern zu einem gemeinsamen BPF-Filter
    ver-odert, damit nur ein einziger Sniffer laufen muss.
    """

    name: str
    bpf: str

    def parse(self, pkt) -> Iterable[Observation]: ...

from __future__ import annotations

from typing import Protocol

from .adjudication import adjudicate_packet
from .models import AdjudicationRecord, EvidencePacket, SinkRule


class AdjudicationBackend(Protocol):
    """Protocol for pluggable adjudication backends."""

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        """Return prosecutor/defender/judge output for one evidence packet."""


class HeuristicAdjudicationBackend:
    """Default local backend used when no external agent is configured."""

    def adjudicate(self, packet: EvidencePacket, sink_rule: SinkRule) -> AdjudicationRecord:
        return adjudicate_packet(packet, sink_rule)

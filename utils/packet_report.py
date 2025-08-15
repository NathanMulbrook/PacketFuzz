#!/usr/bin/env python3
"""
Reusable Packet Report Generator for PacketFuzzing Framework

Generates a formatted, Markdown-style report for any Scapy packet.
Can be used for crash logging, debug output, user export, etc.
"""
import base64
import logging
from typing import Optional, Dict, Any, Union, List
from scapy.packet import Packet

logger = logging.getLogger(__name__)

def write_campaign_summary(
    campaign: Optional[Any],
    campaign_context: Optional[Any],
    file_path: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
    log_dir: str = "logs",
) -> Optional[str]:
    """
    Write a concise end-of-campaign summary log.

    Inputs accepted (based on fuzzing_framework):
    - campaign: FuzzingCampaign instance (for name/target and defaults). Optional.
    - campaign_context: CampaignContext with .stats dict (packets_sent, serialize_failure_count, etc.). Optional.
    - file_path: Optional explicit path to write the summary. If not provided, a file will be created under `log_dir`.
    - extra: Optional dict for additional fields to include.
    - log_dir: Directory to place the summary if file_path not provided.

    Returns: Path to the written summary file, or None if no file was written.
    """
    try:
        stats = {}
        if campaign_context is not None and hasattr(campaign_context, "stats"):
            stats = dict(getattr(campaign_context, "stats", {}) or {})

        packets_sent = int(stats.get("packets_sent", 0) or 0)
        serialize_failures = int(stats.get("serialize_failure_count", 0) or 0)

        campaign_name = None
        target = None
        if campaign is not None:
            campaign_name = getattr(campaign, "name", None) or campaign.__class__.__name__
            target = getattr(campaign, "target", None)

        # Decide output path
        if not file_path:
            import os
            from datetime import datetime
            os.makedirs(log_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = (str(campaign_name).lower().replace(" ", "_") if campaign_name else "campaign")
            file_path = f"{log_dir}/{safe_name}_summary_{timestamp}.log"

        # Compose summary
        lines = []
        lines.append("# PacketFuzz Campaign Summary")
        if campaign_name:
            lines.append(f"Campaign: {campaign_name}")
        if target is not None:
            lines.append(f"Target: {target}")
        lines.append("")
        lines.append("## Stats")
        lines.append(f"- Packets sent: {packets_sent}")
        lines.append(f"- Serialize failures: {serialize_failures}")
        if stats:
            # Include raw stats for completeness
            lines.append(f"- Raw stats: {stats}")
        if extra:
            lines.append("")
            lines.append("## Extra")
            for k, v in extra.items():
                lines.append(f"- {k}: {v}")

        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        logger.info(f"Campaign summary written to {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"Failed to write campaign summary: {e}")
        return None

def write_packet_report(
    packet: Union[Packet, List[Packet]],
    file_path: str,
    mode: str = "a",
    metadata: Optional[Dict[str, Any]] = None,
    campaign_context: Optional[Any] = None,
    crash_info: Optional[Any] = None,
    pcap_path: Optional[str] = None
) -> None:
    """
    Write a formatted packet report to file. Accepts a single Packet or a list of Packets.
    Args:
        packet: Scapy packet or list of packets to report
        file_path: Path to output file
        mode: 'w' for write, 'a' for append
        metadata: Optional dict of metadata
        campaign_context: Optional campaign context
        crash_info: Optional crash info
        pcap_path: Optional path to PCAP file
    """
    # Handle multiple packets: recursively call for each, adding index to metadata
    if isinstance(packet, (list, tuple, set)):
        for idx, pkt in enumerate(packet):
            meta = dict(metadata) if metadata else {}
            meta["index"] = idx + 1
            write_packet_report(
                pkt,
                file_path=file_path,
                mode=mode,
                metadata=meta,
                campaign_context=campaign_context,
                crash_info=crash_info,
                pcap_path=pcap_path
            )
        return
    # Single packet reporting
    with open(file_path, mode) as f:
        f.write("# ==== PACKET REPORT ====\n")
        # Write metadata section
        if metadata:
            f.write("\n## METADATA\n")
            for k, v in metadata.items():
                f.write(f"- **{k}**: {v}\n")
        # Write campaign context if provided
        if campaign_context:
            f.write("\n## CAMPAIGN CONTEXT\n")
            f.write(f"- Campaign: {getattr(campaign_context, 'campaign', None)}\n")
            f.write(f"- Stats: {getattr(campaign_context, 'stats', None)}\n")
        # Write crash info if provided
        if crash_info:
            f.write("\n## CRASH INFO\n")
            for k in ["crash_id", "crash_source", "exception", "timestamp"]:
                v = getattr(crash_info, k, None)
                if v is not None:
                    f.write(f"- **{k}**: {v}\n")
        # Optionally write PCAP file and log errors
        if pcap_path:
            f.write(f"\n## PCAP FILE\n- {pcap_path}\n")
            try:
                if mode == "a":
                    from scapy.utils import PcapWriter
                    writer = PcapWriter(pcap_path, append=True, sync=True)
                    writer.write(packet)
                    writer.close()
                else:
                    from scapy.utils import wrpcap
                    wrpcap(pcap_path, [packet])
            except Exception as e:
                logger.error(f"Failed to write PCAP: {e}")
                f.write(f"(Failed to write PCAP: {e})\n")
        # Write packet summary
        f.write("\n---\n\n## PACKET SUMMARY\n")
        f.write(f"{packet.summary()}\n")
        # Write Scapy dump
        f.write("\n---\n\n## PACKET DETAILS (Scapy Dump)\n")
        f.write("```\n")
        f.write(packet.show(dump=True) or "")
        f.write("\n```\n")
        # Write Python reconstructable packet
        f.write("\n---\n\n## PYTHON RECONSTRUCTABLE PACKET\n")
        f.write("```python\n")
        f.write(repr(packet))
        f.write("\n```\n")
        # Write base64-encoded raw bytes
        f.write("\n---\n\n## BASE64 RAW BYTES\n")
        f.write("```\n")
        f.write(base64.b64encode(bytes(packet)).decode())
        f.write("\n```\n")
        f.write("\n---\n\n")



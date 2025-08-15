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
        verbose = False
        if campaign is not None:
            campaign_name = getattr(campaign, "name", None) or campaign.__class__.__name__
            target = getattr(campaign, "target", None)
            verbose = getattr(campaign, "verbose", False)

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

        # If verbose, write packet reports for failed serializations
        if verbose and campaign_context is not None and hasattr(campaign_context, "fuzz_history"):
            failed_packets = []
            for entry in getattr(campaign_context, "fuzz_history", []):
                # Heuristic: failed serialization if entry.packet is not None and entry.crashed is False and entry.response is None and entry.iteration >= 0 and (entry.packet and not hasattr(entry.packet, "__len__"))
                # But best: if we can mark failed serializations in history, or if campaign_context has a list of failed packets
                # For now, collect all packets where entry.packet is not None and entry.crashed is False and entry.response is None
                # (user can refine this logic as needed)
                if entry.packet is not None and getattr(entry, "crashed", False) is False and getattr(entry, "response", None) is None:
                    failed_packets.append((entry.iteration, entry.packet))
            # If campaign_context has fuzz_history_errors, use that
            if hasattr(campaign_context, "fuzz_history_errors") and getattr(campaign_context, "fuzz_history_errors"):
                for idx, pkt in enumerate(getattr(campaign_context, "fuzz_history_errors")):
                    failed_packets.append((idx, pkt))
            # Write reports
            for idx, pkt in failed_packets:
                try:
                    fail_path = f"{log_dir}/serialize_failure_iter_{idx}.txt"
                    write_packet_report(
                        packet=pkt,
                        file_path=fail_path,
                        mode="w",
                        metadata={
                            "reason": "serialization_failure",
                            "iteration": idx,
                        },
                        campaign_context=campaign_context,
                    )
                except Exception as log_e:
                    logger.warning(f"Failed to write serialize failure report: {log_e}")

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
        # Write base64-encoded raw bytes (best-effort; skip if serialization fails)
        f.write("\n---\n\n## BASE64 RAW BYTES\n")
        f.write("```\n")
        try:
            f.write(base64.b64encode(bytes(packet)).decode())
        except Exception as e:
            logger.error(f"Failed to serialize packet for raw bytes section: {e}")
            f.write(f"(Serialization failed: {e})")
        f.write("\n```\n")
        f.write("\n---\n\n")



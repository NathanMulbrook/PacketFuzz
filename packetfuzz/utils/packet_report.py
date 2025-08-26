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
    log_dir: str = "artifacts/logs",
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
            # Base packet definition summary (repr and summary)
            base_pkt = None
            try:
                base_pkt = campaign.get_packet_with_embedded_config() if hasattr(campaign, 'get_packet_with_embedded_config') else getattr(campaign, 'packet', None)
            except Exception:
                base_pkt = getattr(campaign, 'packet', None)
            base_pkt_summary = None
            base_pkt_repr = None
            if base_pkt is not None:
                try:
                    base_pkt_summary = base_pkt.summary()
                except Exception:
                    base_pkt_summary = "(summary failed)"
                try:
                    base_pkt_repr = repr(base_pkt)
                except Exception:
                    base_pkt_repr = "(repr failed)"

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
        # Mutator usage (if available)
        try:
            # Mutator usage can be stored on the campaign context (if fuzzer exposed it)
            mutator_usage = getattr(campaign_context, 'mutator_usage', None)
            if not mutator_usage and hasattr(campaign, 'last_fuzzer'):
                mutator_usage = getattr(getattr(campaign, 'last_fuzzer'), 'mutator_usage_counts', None)
            if mutator_usage:
                lines.append("")
                lines.append("## Mutator Usage")
                # Sort by count desc
                for k, v in sorted(dict(mutator_usage).items(), key=lambda kv: kv[1], reverse=True):
                    lines.append(f"- {k}: {v}")
        except Exception:
            pass
        # Base packet details (concise)
        if 'base_pkt_summary' in locals() or 'base_pkt_repr' in locals():
            lines.append("")
            lines.append("## Base Packet")
            if base_pkt_summary:
                lines.append(f"- Summary: {base_pkt_summary}")
            if base_pkt_repr:
                lines.append("- Definition:")
                lines.append("```python")
                lines.append(base_pkt_repr)
                lines.append("```")
        if extra:
            lines.append("")
            lines.append("## Extra")
            for k, v in extra.items():
                lines.append(f"- {k}: {v}")

        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        logger.info(f"Campaign summary written to {file_path}")

        # If verbose, consolidate serialization failure reports into one file with a summary
        if verbose and campaign_context is not None:
            failed: List[tuple[int, Any, Optional[str]]] = []  # (iteration, packet, error_str)
            # Prefer explicit error list if provided
            if hasattr(campaign_context, "serialize_failures"):
                try:
                    for item in getattr(campaign_context, "serialize_failures") or []:
                        # item: dict with keys iteration, packet, error
                        it = int(item.get('iteration', -1))
                        pkt = item.get('packet')
                        err = str(item.get('error')) if item.get('error') is not None else None
                        failed.append((it, pkt, err))
                except Exception:
                    pass
            # Fallbacks from history
            if hasattr(campaign_context, "fuzz_history_errors"):
                for idx, pkt in enumerate(getattr(campaign_context, "fuzz_history_errors") or []):
                    failed.append((idx, pkt, None))
            # Single consolidated file
            if failed:
                summary_path = f"{log_dir}/serialize_failures.txt"
                try:
                    with open(summary_path, "w", encoding="utf-8") as sf:
                        sf.write("# Serialization Failures Summary\n\n")
                        # Group by error message
                        from collections import Counter
                        errors = [err or "(unspecified error)" for (_, __, err) in failed]
                        counts = Counter(errors)
                        for err, cnt in counts.most_common():
                            sf.write(f"- {err}: {cnt}\n")
                        sf.write("\n---\n\n")
                        # Append individual packet sections
                        for it, pkt, err in failed:
                            if pkt is None:
                                continue
                            meta = {"reason": "serialization_failure", "iteration": it}
                            if err:
                                meta["error"] = err
                            # Append per-packet report into same file
                            write_packet_report(
                                packet=pkt,
                                file_path=summary_path,
                                mode="a",
                                metadata=meta,
                                campaign_context=campaign_context,
                            )
                except Exception as log_e:
                    logger.warning(f"Failed to write consolidated serialize failure report: {log_e}")

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
        # Write packet summary/dump sections guarded against None
        try:
            f.write("\n---\n\n## PACKET SUMMARY\n")
            f.write(f"{packet.summary()}\n")
        except Exception as e:
            logger.error(f"Failed to summarize packet: {e}")
            f.write(f"(Failed to summarize packet: {e})\n")
        # Write Scapy dump
        f.write("\n---\n\n## PACKET DETAILS (Scapy Dump)\n")
        f.write("```\n")
        try:
            f.write(packet.show(dump=True) or "")
        except Exception as e:
            logger.error(f"Failed to dump packet: {e}")
            f.write(f"(Failed to dump packet: {e})")
        f.write("\n```\n")
        # Write Python reconstructable packet
        f.write("\n---\n\n## PYTHON RECONSTRUCTABLE PACKET\n")
        f.write("```python\n")
        try:
            f.write(repr(packet))
        except Exception as e:
            logger.error(f"Failed to repr packet: {e}")
            f.write(f"# Repr failed: {e}")
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



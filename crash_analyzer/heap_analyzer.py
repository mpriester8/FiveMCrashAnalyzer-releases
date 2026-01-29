"""Heap Timeline Analyzer for FiveM Memory Leak Detection.

Analyzes FiveM heaptimeline JSON files to identify resources with memory leaks.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime


@dataclass
class MemorySnapshot:
    """A single memory snapshot at a point in time."""
    timestamp: float  # seconds since start
    total_allocated: int  # bytes
    allocations_by_resource: Dict[str, int] = field(default_factory=dict)


@dataclass
class ResourceMemoryProfile:
    """Memory profile for a single resource over time."""
    name: str
    samples: List[Tuple[float, int]] = field(default_factory=list)  # (timestamp, bytes)
    
    @property
    def initial_memory(self) -> int:
        return self.samples[0][1] if self.samples else 0
    
    @property
    def final_memory(self) -> int:
        return self.samples[-1][1] if self.samples else 0
    
    @property
    def peak_memory(self) -> int:
        return max(s[1] for s in self.samples) if self.samples else 0
    
    @property
    def memory_growth(self) -> int:
        """Net memory growth from first to last sample."""
        return self.final_memory - self.initial_memory
    
    @property
    def growth_rate_per_minute(self) -> float:
        """Average memory growth rate in bytes per minute."""
        if len(self.samples) < 2:
            return 0.0
        duration_minutes = (self.samples[-1][0] - self.samples[0][0]) / 60.0
        if duration_minutes <= 0:
            return 0.0
        return self.memory_growth / duration_minutes
    
    @property
    def is_leaking(self) -> bool:
        """Heuristic to detect if resource is likely leaking memory (FiveM-tuned)."""
        if len(self.samples) < 3:
            return False
        # Check for consistent growth
        growth = self.memory_growth
        if growth <= 0:
            return False
        # FiveM-specific: Lower threshold since resources are smaller
        # Growth should be significant (> 512KB total)
        if growth < 512 * 1024:
            return False
        # Check if memory is consistently increasing
        increases = 0
        for i in range(1, len(self.samples)):
            if self.samples[i][1] > self.samples[i-1][1]:
                increases += 1
        # FiveM: More strict - if more than 70% of samples show increases, likely a leak
        # This accounts for continuous server operation
        return (increases / (len(self.samples) - 1)) > 0.7
    
    def get_leak_severity(self) -> str:
        """Classify leak severity (FiveM-tuned for continuous server operation)."""
        growth_mb = self.memory_growth / (1024 * 1024)
        rate_mb_min = self.growth_rate_per_minute / (1024 * 1024)
        
        # FiveM servers run continuously - lower thresholds
        # Rate is more important than total for long-running servers
        if growth_mb > 200 or rate_mb_min > 5:
            return "CRITICAL"
        elif growth_mb > 50 or rate_mb_min > 2:
            return "HIGH"
        elif growth_mb > 20 or rate_mb_min > 0.5:
            return "MEDIUM"
        else:
            return "LOW"


@dataclass
class HeapAnalysisResult:
    """Results from heap timeline analysis."""
    file_path: str
    duration_seconds: float = 0.0
    total_snapshots: int = 0
    
    # Overall stats
    initial_heap_size: int = 0
    final_heap_size: int = 0
    peak_heap_size: int = 0
    total_growth: int = 0
    
    # Per-resource profiles
    resource_profiles: Dict[str, ResourceMemoryProfile] = field(default_factory=dict)
    
    # Identified leaks (sorted by severity)
    leaking_resources: List[ResourceMemoryProfile] = field(default_factory=list)
    
    # Raw data
    snapshots: List[MemorySnapshot] = field(default_factory=list)
    
    # Errors during parsing
    errors: List[str] = field(default_factory=list)


class HeapTimelineAnalyzer:
    """Analyzes FiveM heap timeline files for memory leaks."""
    
    def __init__(self):
        self.result: Optional[HeapAnalysisResult] = None
    
    def analyze_file(self, file_path: str) -> HeapAnalysisResult:
        """Analyze a heap timeline JSON file."""
        self.result = HeapAnalysisResult(file_path=file_path)
        
        if not os.path.exists(file_path):
            self.result.errors.append(f"File not found: {file_path}")
            return self.result
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            self.result.errors.append(f"Invalid JSON: {e}")
            return self.result
        except Exception as e:
            self.result.errors.append(f"Error reading file: {e}")
            return self.result
        
        # Parse based on format
        if isinstance(data, list):
            self._parse_array_format(data)
        elif isinstance(data, dict):
            self._parse_dict_format(data)
        else:
            self.result.errors.append("Unknown heap timeline format")
            return self.result
        
        # Analyze for leaks
        self._identify_leaks()
        
        return self.result
    
    def _parse_array_format(self, data: List[Dict]) -> None:
        """Parse heap timeline in array format (list of snapshots)."""
        for i, entry in enumerate(data):
            try:
                snapshot = self._parse_snapshot(entry, i)
                if snapshot:
                    self.result.snapshots.append(snapshot)
                    self._update_resource_profiles(snapshot)
            except Exception as e:
                self.result.errors.append(f"Error parsing snapshot {i}: {e}")
        
        self._compute_overall_stats()
    
    def _parse_dict_format(self, data: Dict) -> None:
        """Parse heap timeline in dict format (FiveM format variations)."""
        # Check for different FiveM heap timeline formats
        
        # Format 0: V8 Heap Snapshot (Chrome DevTools format)
        # {"snapshot": {...}, "nodes": [...], "edges": [...], "strings": [...]}
        if "snapshot" in data and "nodes" in data and "strings" in data:
            self._parse_v8_heap_snapshot(data)
            return
        
        # Format 1: {"snapshots": [...]}
        if "snapshots" in data:
            self._parse_array_format(data["snapshots"])
            return
        
        # Format 2: {"timeline": [...]}
        if "timeline" in data:
            self._parse_array_format(data["timeline"])
            return
        
        # Format 3: {"resources": {"resource_name": {...}}}
        if "resources" in data:
            self._parse_resources_format(data["resources"])
            return
        
        # Format 4: Direct resource -> allocation mapping per timestamp
        # {"timestamp1": {"resource1": size, ...}, ...}
        if all(self._is_timestamp_key(k) for k in list(data.keys())[:5]):
            self._parse_timestamp_dict_format(data)
            return
        
        # Format 5: Resource-centric {"resource_name": [sizes...], ...}
        if all(isinstance(v, list) for v in list(data.values())[:5]):
            self._parse_resource_list_format(data)
            return
        
        self.result.errors.append("Could not determine heap timeline format")
    
    def _parse_v8_heap_snapshot(self, data: Dict) -> None:
        """Parse V8 Heap Snapshot format (Chrome DevTools / FiveM heaptimeline).
        
        This format contains:
        - snapshot: metadata about node/edge field structure
        - nodes: flat array of node data (7 fields per node)
        - edges: flat array of edge data (3 fields per edge)
        - strings: string table for name lookups
        
        We traverse the object graph to attribute memory to FiveM resources
        by finding resource references and following edges to child objects.
        """
        try:
            meta = data["snapshot"]["meta"]
            node_fields = meta["node_fields"]
            edge_fields = meta["edge_fields"]
            node_count = data["snapshot"]["node_count"]
            nodes = data["nodes"]
            edges = data["edges"]
            strings = data["strings"]
            
            # Node field positions
            fields_per_node = len(node_fields)
            n_name_idx = node_fields.index("name") if "name" in node_fields else 1
            n_size_idx = node_fields.index("self_size") if "self_size" in node_fields else 3
            n_edge_count_idx = node_fields.index("edge_count") if "edge_count" in node_fields else 4
            
            # Edge field positions
            fields_per_edge = len(edge_fields)
            e_to_node_idx = edge_fields.index("to_node") if "to_node" in edge_fields else 2
            
            # Patterns to extract FiveM resource names
            resource_pattern = re.compile(r'https://([a-zA-Z0-9_-]+)/')
            cfx_pattern = re.compile(r'cfx-nui-([a-zA-Z0-9_-]+)')
            resource_path_pattern = re.compile(r'@([a-zA-Z0-9_-]+)/')
            
            # Ignored names
            ignored = {'cfx', 'nui', 'localhost', 'fonts', 'images', 'assets', 
                       'http', 'https', 'www', 'cdn', 'api', 'static', 'node_modules',
                       'webpack', 'chunk', 'vendor', 'common', 'runtime'}
            
            # Step 1: Find strings that reference resources
            string_to_resources: Dict[int, set] = {}
            
            for i, s in enumerate(strings):
                if not isinstance(s, str) or len(s) < 5:
                    continue
                
                found = set()
                for m in resource_pattern.findall(s):
                    if m.lower() not in ignored and len(m) > 2:
                        found.add(m)
                for m in cfx_pattern.findall(s):
                    if m.lower() not in ignored:
                        found.add(m)
                for m in resource_path_pattern.findall(s):
                    if m.lower() not in ignored:
                        found.add(m)
                
                if found:
                    string_to_resources[i] = found
            
            # Step 2: Mark nodes that directly reference resources (seed nodes)
            node_resources: List[Optional[set]] = [None] * node_count
            resource_memory: Dict[str, int] = {}
            resource_objects: Dict[str, int] = {}
            
            for node_idx in range(node_count):
                node_offset = node_idx * fields_per_node
                name_string_idx = nodes[node_offset + n_name_idx]
                
                if name_string_idx in string_to_resources:
                    node_resources[node_idx] = string_to_resources[name_string_idx].copy()
                    
                    # Add this node's memory to each resource
                    self_size = nodes[node_offset + n_size_idx]
                    for res in node_resources[node_idx]:
                        resource_memory[res] = resource_memory.get(res, 0) + self_size
                        resource_objects[res] = resource_objects.get(res, 0) + 1
            
            # Step 3: Propagate resource ownership DOWN through edges (parent -> children)
            # Do a single pass following edges, propagating resource tags
            # Limit propagation depth to avoid exponential growth
            
            max_depth = 5
            
            for depth in range(max_depth):
                edge_offset = 0
                propagated = 0
                
                for node_idx in range(node_count):
                    node_offset = node_idx * fields_per_node
                    node_edge_count = nodes[node_offset + n_edge_count_idx]
                    
                    # If this node has resource tags, propagate to children
                    parent_resources = node_resources[node_idx]
                    
                    for _ in range(node_edge_count):
                        if edge_offset + e_to_node_idx >= len(edges):
                            break
                        
                        # Get child node
                        to_node_offset = edges[edge_offset + e_to_node_idx]
                        child_idx = to_node_offset // fields_per_node
                        edge_offset += fields_per_edge
                        
                        if child_idx >= node_count:
                            continue
                        
                        # Propagate resources from parent to child
                        if parent_resources is not None:
                            child_offset = child_idx * fields_per_node
                            child_size = nodes[child_offset + n_size_idx]
                            
                            if node_resources[child_idx] is None:
                                # Child has no resources yet - inherit from parent
                                node_resources[child_idx] = parent_resources.copy()
                                propagated += 1
                                
                                # Add child's memory to resources
                                for res in parent_resources:
                                    resource_memory[res] = resource_memory.get(res, 0) + child_size
                                    resource_objects[res] = resource_objects.get(res, 0) + 1
                            else:
                                # Child already has resources - merge (add new ones only)
                                new_resources = parent_resources - node_resources[child_idx]
                                if new_resources:
                                    node_resources[child_idx].update(new_resources)
                                    propagated += 1
                                    for res in new_resources:
                                        resource_memory[res] = resource_memory.get(res, 0) + child_size
                                        resource_objects[res] = resource_objects.get(res, 0) + 1
                
                # Stop if no more propagation happening
                if propagated == 0:
                    break
            
            # Step 4: Calculate total heap size
            total_heap_size = 0
            for node_idx in range(node_count):
                offset = node_idx * fields_per_node
                total_heap_size += nodes[offset + n_size_idx]
            
            # Step 5: Create resource profiles
            for res_name, mem_size in resource_memory.items():
                profile = ResourceMemoryProfile(name=res_name)
                profile.samples.append((0.0, mem_size))
                self.result.resource_profiles[res_name] = profile
            
            # Store stats
            self.result.initial_heap_size = total_heap_size
            self.result.final_heap_size = total_heap_size
            self.result.peak_heap_size = total_heap_size
            self.result.total_snapshots = 1
            
            # Identify large consumers
            self._identify_large_consumers()
            
        except Exception as e:
            import traceback
            self.result.errors.append(f"Error parsing V8 heap snapshot: {e}")
            self.result.errors.append(traceback.format_exc())
    
    def _identify_large_consumers(self) -> None:
        """For single snapshots, identify resources using most memory (FiveM-tuned)."""
        # Sort profiles by memory usage
        sorted_profiles = sorted(
            self.result.resource_profiles.values(),
            key=lambda p: p.final_memory,
            reverse=True
        )
        
        # Mark top consumers as "leaking" for display purposes
        # (They're not necessarily leaking, just using lots of memory)
        total_attributed = sum(p.final_memory for p in sorted_profiles)
        
        for profile in sorted_profiles:
            # FiveM-specific: Flag resources using > 10MB (high for NUI)
            # or > 3% of attributed memory (to catch relative hogs)
            if profile.final_memory > 10 * 1024 * 1024:
                self.result.leaking_resources.append(profile)
            elif total_attributed > 0 and (profile.final_memory / total_attributed) > 0.03:
                self.result.leaking_resources.append(profile)
    
    def _is_timestamp_key(self, key: str) -> bool:
        """Check if a key looks like a timestamp."""
        try:
            float(key)
            return True
        except ValueError:
            return key.isdigit() or re.match(r'\d+\.?\d*', key) is not None
    
    def _parse_snapshot(self, entry: Dict, index: int) -> Optional[MemorySnapshot]:
        """Parse a single snapshot entry."""
        # Try various field names for timestamp
        timestamp = None
        for ts_field in ['timestamp', 'time', 't', 'ts', 'msec', 'sec']:
            if ts_field in entry:
                timestamp = float(entry[ts_field])
                # Convert milliseconds to seconds if needed
                if timestamp > 1e10:
                    timestamp /= 1000.0
                break
        
        if timestamp is None:
            timestamp = float(index)  # Use index as timestamp
        
        # Get total allocated
        total = 0
        for total_field in ['total', 'totalAllocated', 'total_allocated', 'heap_size', 'size']:
            if total_field in entry:
                total = int(entry[total_field])
                break
        
        # Get per-resource allocations
        allocations = {}
        
        # Check for resources field
        resources = entry.get('resources') or entry.get('allocations') or entry.get('byResource')
        if isinstance(resources, dict):
            for res_name, size in resources.items():
                if isinstance(size, (int, float)):
                    allocations[res_name] = int(size)
                elif isinstance(size, dict):
                    # Nested format: {"size": 123, "count": 456}
                    allocations[res_name] = int(size.get('size', 0) or size.get('bytes', 0))
        
        # Also check for inline resource fields
        for key, value in entry.items():
            if key.startswith('resource:') or key.startswith('res:'):
                res_name = key.split(':', 1)[1]
                if isinstance(value, (int, float)):
                    allocations[res_name] = int(value)
        
        return MemorySnapshot(
            timestamp=timestamp,
            total_allocated=total,
            allocations_by_resource=allocations
        )
    
    def _parse_resources_format(self, resources: Dict) -> None:
        """Parse format where resources have their own timeline."""
        # {"resource_name": {"timeline": [...]}}
        for res_name, res_data in resources.items():
            if isinstance(res_data, dict) and 'timeline' in res_data:
                profile = ResourceMemoryProfile(name=res_name)
                for i, size in enumerate(res_data['timeline']):
                    timestamp = res_data.get('timestamps', [i])[i] if i < len(res_data.get('timestamps', [])) else float(i)
                    profile.samples.append((timestamp, int(size)))
                self.result.resource_profiles[res_name] = profile
        
        self._compute_overall_stats()
    
    def _parse_timestamp_dict_format(self, data: Dict) -> None:
        """Parse format: {"timestamp": {"resource": size}}."""
        timestamps = sorted((float(k), v) for k, v in data.items())
        
        for ts, resources in timestamps:
            allocations = {}
            total = 0
            for res_name, size in resources.items():
                if isinstance(size, (int, float)):
                    allocations[res_name] = int(size)
                    total += int(size)
            
            snapshot = MemorySnapshot(
                timestamp=ts,
                total_allocated=total,
                allocations_by_resource=allocations
            )
            self.result.snapshots.append(snapshot)
            self._update_resource_profiles(snapshot)
        
        self._compute_overall_stats()
    
    def _parse_resource_list_format(self, data: Dict) -> None:
        """Parse format: {"resource_name": [size1, size2, ...]}."""
        max_len = max(len(v) for v in data.values()) if data else 0
        
        for res_name, sizes in data.items():
            profile = ResourceMemoryProfile(name=res_name)
            for i, size in enumerate(sizes):
                profile.samples.append((float(i), int(size)))
            self.result.resource_profiles[res_name] = profile
        
        self._compute_overall_stats()
    
    def _update_resource_profiles(self, snapshot: MemorySnapshot) -> None:
        """Update resource profiles from a snapshot."""
        for res_name, size in snapshot.allocations_by_resource.items():
            if res_name not in self.result.resource_profiles:
                self.result.resource_profiles[res_name] = ResourceMemoryProfile(name=res_name)
            self.result.resource_profiles[res_name].samples.append((snapshot.timestamp, size))
    
    def _compute_overall_stats(self) -> None:
        """Compute overall heap statistics."""
        if self.result.snapshots:
            self.result.total_snapshots = len(self.result.snapshots)
            self.result.initial_heap_size = self.result.snapshots[0].total_allocated
            self.result.final_heap_size = self.result.snapshots[-1].total_allocated
            self.result.peak_heap_size = max(s.total_allocated for s in self.result.snapshots)
            self.result.total_growth = self.result.final_heap_size - self.result.initial_heap_size
            
            if len(self.result.snapshots) >= 2:
                self.result.duration_seconds = (
                    self.result.snapshots[-1].timestamp - self.result.snapshots[0].timestamp
                )
        elif self.result.resource_profiles:
            # Compute from profiles
            self.result.total_snapshots = max(
                len(p.samples) for p in self.result.resource_profiles.values()
            )
            
            # Sum up resource memory
            all_timestamps = set()
            for profile in self.result.resource_profiles.values():
                for ts, _ in profile.samples:
                    all_timestamps.add(ts)
            
            if all_timestamps:
                min_ts = min(all_timestamps)
                max_ts = max(all_timestamps)
                self.result.duration_seconds = max_ts - min_ts
    
    def _identify_leaks(self) -> None:
        """Identify resources with memory leaks."""
        leaking = []
        
        for profile in self.result.resource_profiles.values():
            if profile.is_leaking:
                leaking.append(profile)
        
        # Sort by severity (growth amount)
        leaking.sort(key=lambda p: p.memory_growth, reverse=True)
        self.result.leaking_resources = leaking
    
    def generate_report(self, result: Optional[HeapAnalysisResult] = None) -> str:
        """Generate a human-readable report."""
        result = result or self.result
        if not result:
            return "No analysis result available."
        
        lines = []
        
        # Detect if this is a V8 snapshot (single point-in-time)
        is_v8_snapshot = result.total_snapshots == 1 and result.duration_seconds == 0
        
        if is_v8_snapshot:
            lines.append("=" * 70)
            lines.append("V8 HEAP SNAPSHOT ANALYSIS - MEMORY USAGE BY RESOURCE")
            lines.append("=" * 70)
        else:
            lines.append("=" * 70)
            lines.append("HEAP TIMELINE ANALYSIS - MEMORY LEAK DETECTION")
            lines.append("=" * 70)
        lines.append("")
        
        lines.append(f"File: {os.path.basename(result.file_path)}")
        if not is_v8_snapshot:
            lines.append(f"Duration: {result.duration_seconds:.1f} seconds ({result.duration_seconds/60:.1f} minutes)")
        lines.append(f"Snapshots: {result.total_snapshots}")
        lines.append("")
        
        # Overall memory stats
        lines.append("-" * 40)
        lines.append("OVERALL HEAP STATISTICS:")
        lines.append("-" * 40)
        if is_v8_snapshot:
            lines.append(f"  Total Heap Size: {self._format_bytes(result.final_heap_size)}")
            attributed = sum(p.final_memory for p in result.resource_profiles.values())
            lines.append(f"  Attributed to Resources: {self._format_bytes(attributed)}")
            lines.append(f"  Resources Found: {len(result.resource_profiles)}")
        else:
            lines.append(f"  Initial Heap: {self._format_bytes(result.initial_heap_size)}")
            lines.append(f"  Final Heap:   {self._format_bytes(result.final_heap_size)}")
            lines.append(f"  Peak Heap:    {self._format_bytes(result.peak_heap_size)}")
            lines.append(f"  Total Growth: {self._format_bytes(result.total_growth)}")
            if result.duration_seconds > 0:
                rate = result.total_growth / (result.duration_seconds / 60)
                lines.append(f"  Growth Rate:  {self._format_bytes(rate)}/minute")
        lines.append("")
        
        # Memory consumers / leaks
        if result.leaking_resources:
            if is_v8_snapshot:
                lines.append("=" * 70)
                lines.append(f"⚠ HIGH MEMORY CONSUMERS: {len(result.leaking_resources)} RESOURCES")
                lines.append("=" * 70)
                lines.append("")
                lines.append("(Note: This is a single snapshot - cannot detect leaks over time)")
                lines.append("(Resources below are using significant memory)")
                lines.append("")
            else:
                lines.append("=" * 70)
                lines.append(f"⚠ MEMORY LEAKS DETECTED: {len(result.leaking_resources)} RESOURCES")
                lines.append("=" * 70)
                lines.append("")
            
            for i, profile in enumerate(result.leaking_resources, 1):
                if is_v8_snapshot:
                    # For V8 snapshots, classify by absolute memory usage
                    mem_mb = profile.final_memory / (1024 * 1024)
                    if mem_mb > 50:
                        severity, marker = "HIGH", "🟠"
                    elif mem_mb > 20:
                        severity, marker = "MEDIUM", "🟡"
                    else:
                        severity, marker = "LOW", "🟢"
                    
                    lines.append(f"#{i} {marker} [{severity}] {profile.name}")
                    lines.append(f"   Memory Usage: {self._format_bytes(profile.final_memory)}")
                else:
                    severity = profile.get_leak_severity()
                    severity_marker = {
                        "CRITICAL": "🔴",
                        "HIGH": "🟠",
                        "MEDIUM": "🟡",
                        "LOW": "🟢"
                    }.get(severity, "⚪")
                    
                    lines.append(f"#{i} {severity_marker} [{severity}] {profile.name}")
                    lines.append(f"   Initial: {self._format_bytes(profile.initial_memory)}")
                    lines.append(f"   Final:   {self._format_bytes(profile.final_memory)}")
                    lines.append(f"   Peak:    {self._format_bytes(profile.peak_memory)}")
                    lines.append(f"   Growth:  {self._format_bytes(profile.memory_growth)} (+{self._percent_change(profile.initial_memory, profile.final_memory)})")
                    lines.append(f"   Rate:    {self._format_bytes(profile.growth_rate_per_minute)}/minute")
                lines.append("")
        else:
            lines.append("-" * 40)
            lines.append("✓ No significant memory leaks detected.")
            lines.append("-" * 40)
            lines.append("")
        
        # All resources summary
        if result.resource_profiles:
            lines.append("-" * 40)
            lines.append("ALL RESOURCES BY MEMORY USAGE:")
            lines.append("-" * 40)
            
            # Sort by final memory
            sorted_profiles = sorted(
                result.resource_profiles.values(),
                key=lambda p: p.final_memory,
                reverse=True
            )
            
            for profile in sorted_profiles[:20]:
                growth_indicator = ""
                if profile.memory_growth > 1024 * 1024:  # > 1MB growth
                    growth_indicator = f" (+{self._format_bytes(profile.memory_growth)})"
                elif profile.memory_growth < -1024 * 1024:  # > 1MB decrease
                    growth_indicator = f" ({self._format_bytes(profile.memory_growth)})"
                
                leak_marker = " ⚠ LEAK" if profile in result.leaking_resources else ""
                
                lines.append(f"  {profile.name}: {self._format_bytes(profile.final_memory)}{growth_indicator}{leak_marker}")
            
            if len(sorted_profiles) > 20:
                lines.append(f"  ... and {len(sorted_profiles) - 20} more resources")
            lines.append("")
        
        # Errors
        if result.errors:
            lines.append("-" * 40)
            lines.append("PARSING ERRORS:")
            lines.append("-" * 40)
            for err in result.errors:
                lines.append(f"  - {err}")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def _format_bytes(self, size: float) -> str:
        """Format bytes as human-readable string."""
        if abs(size) < 1024:
            return f"{size:.0f} B"
        elif abs(size) < 1024 * 1024:
            return f"{size/1024:.1f} KB"
        elif abs(size) < 1024 * 1024 * 1024:
            return f"{size/(1024*1024):.2f} MB"
        else:
            return f"{size/(1024*1024*1024):.2f} GB"
    
    def _percent_change(self, initial: int, final: int) -> str:
        """Calculate percent change."""
        if initial == 0:
            return "N/A"
        change = ((final - initial) / initial) * 100
        return f"{change:+.1f}%"

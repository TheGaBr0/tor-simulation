import time
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
import statistics


class CorrelationAttackAnalyzer:
    """
    Implements end-to-end timing correlation attacks on Tor circuits.
    Analyzes timestamp patterns from compromised guard and exit nodes to link
    anonymous traffic flows and deanonymize users.
    """
    
    def __init__(self, compromised_nodes: List, time_window: float = 2.0, 
                 correlation_threshold: float = 0.7):
        """
        Initialize the correlation attack analyzer.
        """
        self.compromised_nodes = compromised_nodes
        self.time_window = time_window
        self.correlation_threshold = correlation_threshold
        
        # Categorize compromised nodes by their position in the network
        self.entry_nodes = [node for node in compromised_nodes if node.type == "guard"]
        self.exit_nodes = [node for node in compromised_nodes if node.type == "exit"]
        self.middle_nodes = [node for node in compromised_nodes if node.type == "relay"]
        
    def collect_timing_data(self) -> Dict[str, List[float]]:
        """
        Extract timing information from all compromised nodes.
        """
        timing_data = {}
        for node in self.compromised_nodes:
            timing_data[node.id] = node.timing_data.copy()
        return timing_data
    
    def _create_time_series(self, timestamps: List[float]) -> List[Tuple[float, int]]:
        """
        Convert raw timestamps into a time series with fixed intervals.
        Groups events into 100ms buckets for pattern analysis.
        """
        if not timestamps:
            return []
        
        sorted_times = sorted(timestamps)
        
        # Use 100ms buckets for fine-grained correlation
        bucket_size = 0.1
        min_time = sorted_times[0]
        max_time = sorted_times[-1]
        
        # Count events per time bucket
        buckets = defaultdict(int)
        for ts in sorted_times:
            bucket = int((ts - min_time) / bucket_size)
            buckets[bucket] += 1
        
        # Generate time series representation
        time_series = [(min_time + bucket * bucket_size, count) 
                       for bucket, count in sorted(buckets.items())]
        
        return time_series
    
    def _calculate_correlation_score(self, entry_times: List[float], 
                                     exit_times: List[float]) -> float:
        """
        Calculate timing correlation score between entry and exit node traffic.
        Uses bidirectional greedy matching with balance penalties.
        
        Algorithm:
        1. For each entry event, find the closest exit event within time_window
        2. Use greedy matching - each exit event can only match once
        3. Calculate base score: (matched_events) / (total_events)
        4. Apply penalty if entry/exit event counts are significantly imbalanced
        """
        if not entry_times or not exit_times:
            return 0.0
        
        # Convert to time series for pattern analysis
        entry_series = self._create_time_series(entry_times)
        exit_series = self._create_time_series(exit_times)
        
        if not entry_series or not exit_series:
            return 0.0
        
        # Extract temporal bounds
        entry_start = entry_series[0][0]
        entry_end = entry_series[-1][0]
        exit_start = exit_series[0][0]
        exit_end = exit_series[-1][0]
        
        # Check for temporal overlap (accounting for network propagation delay)
        max_delay = 1.0  # Maximum expected Tor latency
        
        if exit_start > entry_end + max_delay or entry_start > exit_end + max_delay:
            return 0.0  # No temporal overlap possible
        
        # Perform bidirectional greedy matching
        entry_matched = 0
        used_exits = set()
        
        # Match each entry event to the closest available exit event
        for entry_time in entry_times:
            best_match = None
            best_distance = float('inf')
            
            for i, exit_time in enumerate(exit_times):
                if i in used_exits:
                    continue  # This exit event already matched
                    
                distance = abs(exit_time - entry_time)
                
                if distance <= self.time_window and distance < best_distance:
                    best_match = i
                    best_distance = distance
            
            if best_match is not None:
                entry_matched += 1
                used_exits.add(best_match)
        
        exit_matched = len(used_exits)
        
        # Calculate base correlation score
        total_events = len(entry_times) + len(exit_times)
        matched_events = entry_matched + exit_matched
        base_score = matched_events / total_events if total_events > 0 else 0.0
        
        # Apply balance penalty for asymmetric matching
        entry_ratio = entry_matched / len(entry_times) if len(entry_times) > 0 else 0.0
        exit_ratio = exit_matched / len(exit_times) if len(exit_times) > 0 else 0.0
        balance_factor = (min(entry_ratio, exit_ratio) / max(entry_ratio, exit_ratio) 
                         if max(entry_ratio, exit_ratio) > 0 else 0.0)
        
        # Final score: 70% base + 30% balance
        correlation = base_score * (0.7 + 0.3 * balance_factor)
        
        return min(correlation, 1.0)
    
    def _find_session_boundaries(self, timestamps: List[float], 
                                 gap_threshold: float = 5.0) -> List[Tuple[float, float]]:
        """
        Identify distinct communication sessions based on temporal gaps.
        Sessions are separated when inactivity exceeds the gap threshold.
        """
        if not timestamps:
            return []
        
        sorted_times = sorted(timestamps)
        sessions = []
        session_start = sorted_times[0]
        
        for i in range(1, len(sorted_times)):
            gap = sorted_times[i] - sorted_times[i-1]
            if gap > gap_threshold:
                # End current session and start a new one
                sessions.append((session_start, sorted_times[i-1]))
                session_start = sorted_times[i]
        
        # Add the final session
        sessions.append((session_start, sorted_times[-1]))
        
        return sessions
    
    def get_timing_statistics(self) -> Dict:
        """
        Compute statistical metrics for timing patterns at each compromised node.
        """
        timing_data = self.collect_timing_data()
        stats = {}
        
        for node_id, timestamps in timing_data.items():
            if len(timestamps) < 2:
                continue
                
            sorted_times = sorted(timestamps)
            # Calculate gaps between consecutive events
            inter_arrival_times = [sorted_times[i+1] - sorted_times[i] 
                                  for i in range(len(sorted_times)-1)]
            
            stats[node_id] = {
                'total_events': len(timestamps),
                'mean_inter_arrival': statistics.mean(inter_arrival_times) if inter_arrival_times else 0,
                'std_inter_arrival': statistics.stdev(inter_arrival_times) if len(inter_arrival_times) > 1 else 0,
                'min_gap': min(inter_arrival_times) if inter_arrival_times else 0,
                'max_gap': max(inter_arrival_times) if inter_arrival_times else 0
            }
        
        return stats
    
    def _calculate_confidence(self, correlation_score: float, 
                            entry_events: int, exit_events: int) -> str:
        """
        Determine confidence level for a single correlation session.
        """
        min_events = min(entry_events, exit_events)
        
        if correlation_score >= 0.85 and min_events >= 15:
            return "HIGH"
        elif correlation_score >= 0.65 and min_events >= 8:
            return "MEDIUM"
        else:
            return "LOW"
    
    def perform_correlation_attack(self) -> List[Dict]:
        """
        Execute basic timing correlation attack on collected data.
        Links entry and exit traffic by analyzing individual sessions.
        """
        timing_data = self.collect_timing_data()
        correlated_flows = []
        
        # Deduplicate nodes by ID
        unique_entry_nodes = list({node.id: node for node in self.entry_nodes}.values())
        unique_exit_nodes = list({node.id: node for node in self.exit_nodes}.values())
        
        # Analyze each guard node
        for entry_node in unique_entry_nodes:
            entry_times = timing_data.get(entry_node.id, [])
            if not entry_times:
                continue
            
            entry_sessions = self._find_session_boundaries(entry_times)
            
            # Try correlating with each exit node
            for exit_node in unique_exit_nodes:
                exit_times = timing_data.get(exit_node.id, [])
                if not exit_times:
                    continue
                
                exit_sessions = self._find_session_boundaries(exit_times)
                
                # Correlate each pair of sessions
                for entry_start, entry_end in entry_sessions:
                    entry_session_times = [t for t in entry_times 
                                          if entry_start <= t <= entry_end]
                    
                    for exit_start, exit_end in exit_sessions:
                        exit_session_times = [t for t in exit_times 
                                             if exit_start <= t <= exit_end]
                        
                        # Calculate correlation score
                        score = self._calculate_correlation_score(
                            entry_session_times, exit_session_times
                        )
                        
                        # Record flows that exceed the threshold
                        if score >= self.correlation_threshold:
                            correlated_flows.append({
                                'entry_node': entry_node.id,
                                'entry_ip': entry_node.ip,
                                'exit_node': exit_node.id,
                                'exit_ip': exit_node.ip,
                                'correlation_score': score,
                                'entry_session': (entry_start, entry_end),
                                'exit_session': (exit_start, exit_end),
                                'entry_events': len(entry_session_times),
                                'exit_events': len(exit_session_times),
                                'session_duration': entry_end - entry_start,
                                'confidence': self._calculate_confidence(score, 
                                    len(entry_session_times), len(exit_session_times))
                            })
        
        # Remove duplicate flows (keep highest scoring)
        unique_flows = {}
        for flow in correlated_flows:
            key = (flow['entry_node'], flow['exit_node'], 
                   round(flow['entry_session'][0], 2), 
                   round(flow['exit_session'][0], 2))
            
            if key not in unique_flows or flow['correlation_score'] > unique_flows[key]['correlation_score']:
                unique_flows[key] = flow
        
        correlated_flows = list(unique_flows.values())
        correlated_flows.sort(key=lambda x: x['correlation_score'], reverse=True)
        
        return correlated_flows
    
    def perform_cumulative_correlation_attack(self) -> List[Dict]:
        """
        Execute advanced correlation attack with cumulative evidence gathering.
        Aggregates data across multiple sessions to build confidence over time.
        Provides bonus scoring for consistent correlations across sessions.
        """
        timing_data = self.collect_timing_data()
        
        # Deduplicate nodes
        unique_entry_nodes = list({node.id: node for node in self.entry_nodes}.values())
        unique_exit_nodes = list({node.id: node for node in self.exit_nodes}.values())
        
        # Aggregate session data per circuit
        circuit_sessions = {}
        
        # Analyze all entry-exit pairs
        for entry_node in unique_entry_nodes:
            entry_times = timing_data.get(entry_node.id, [])
            if not entry_times:
                continue
            
            entry_sessions = self._find_session_boundaries(entry_times)
            
            for exit_node in unique_exit_nodes:
                exit_times = timing_data.get(exit_node.id, [])
                if not exit_times:
                    continue
                
                exit_sessions = self._find_session_boundaries(exit_times)
                circuit_key = (entry_node.id, exit_node.id)
                
                # Collect all correlating sessions for this circuit
                for entry_start, entry_end in entry_sessions:
                    entry_session_times = [t for t in entry_times 
                                          if entry_start <= t <= entry_end]
                    
                    for exit_start, exit_end in exit_sessions:
                        exit_session_times = [t for t in exit_times 
                                             if exit_start <= t <= exit_end]
                        
                        score = self._calculate_correlation_score(
                            entry_session_times, exit_session_times
                        )
                        
                        # Store all sessions above minimum threshold for cumulative analysis
                        if score > 0.5:
                            if circuit_key not in circuit_sessions:
                                circuit_sessions[circuit_key] = {
                                    'entry_node': entry_node,
                                    'exit_node': exit_node,
                                    'sessions': []
                                }
                            
                            circuit_sessions[circuit_key]['sessions'].append({
                                'entry_session': (entry_start, entry_end),
                                'exit_session': (exit_start, exit_end),
                                'entry_times': entry_session_times,
                                'exit_times': exit_session_times,
                                'individual_score': score,
                                'entry_events': len(entry_session_times),
                                'exit_events': len(exit_session_times)
                            })
        
        # Calculate cumulative scores for each circuit
        correlated_flows = []
        
        for circuit_key, circuit_data in circuit_sessions.items():
            sessions = circuit_data['sessions']
            if not sessions:
                continue
            
            # Aggregate timing data across all sessions
            all_entry_times = []
            all_exit_times = []
            total_entry_events = 0
            total_exit_events = 0
            
            for session in sessions:
                all_entry_times.extend(session['entry_times'])
                all_exit_times.extend(session['exit_times'])
                total_entry_events += session['entry_events']
                total_exit_events += session['exit_events']
            
            # Compute cumulative correlation score
            cumulative_score = self._calculate_correlation_score(
                all_entry_times, all_exit_times
            )
            
            # Calculate consistency metrics
            session_scores = [s['individual_score'] for s in sessions]
            avg_session_score = statistics.mean(session_scores)
            score_consistency = 1.0 - statistics.stdev(session_scores) if len(session_scores) > 1 else 1.0
            
            # Apply bonuses for multiple consistent sessions
            session_bonus = min(0.1 * (len(sessions) - 1), 0.3)  # Up to 30% bonus
            consistency_bonus = 0.05 * score_consistency  # Up to 5% bonus
            
            # Compute final weighted score
            final_score = min(cumulative_score + session_bonus + consistency_bonus, 1.0)
            
            # Determine cumulative confidence level
            cumulative_confidence = self._calculate_cumulative_confidence(
                final_score, total_entry_events, total_exit_events, len(sessions)
            )
            
            # Only report flows above the threshold
            if final_score >= self.correlation_threshold:
                entry_node = circuit_data['entry_node']
                exit_node = circuit_data['exit_node']
                
                first_session = min(sessions, key=lambda s: s['entry_session'][0])
                last_session = max(sessions, key=lambda s: s['entry_session'][1])
                
                total_duration = last_session['entry_session'][1] - first_session['entry_session'][0]
                
                correlated_flows.append({
                    'entry_node': entry_node.id,
                    'entry_ip': entry_node.ip,
                    'exit_node': exit_node.id,
                    'exit_ip': exit_node.ip,
                    'correlation_score': final_score,
                    'cumulative_score': cumulative_score,
                    'session_bonus': session_bonus,
                    'consistency_bonus': consistency_bonus,
                    'entry_events': total_entry_events,
                    'exit_events': total_exit_events,
                    'num_sessions': len(sessions),
                    'session_details': sessions,
                    'total_duration': total_duration,
                    'first_seen': first_session['entry_session'][0],
                    'last_seen': last_session['entry_session'][1],
                    'confidence': cumulative_confidence,
                    'avg_session_score': avg_session_score,
                    'score_consistency': score_consistency
                })
        
        # Sort by final score (highest confidence first)
        correlated_flows.sort(key=lambda x: x['correlation_score'], reverse=True)
        
        return correlated_flows
    
    def _calculate_cumulative_confidence(self, score: float, entry_events: int, 
                                        exit_events: int, num_sessions: int) -> str:
        """
        Calculate confidence level with cumulative evidence weighting.
        More sessions and events increase confidence in the correlation.
        """
        min_events = min(entry_events, exit_events)
        
        # Adjusted thresholds for cumulative analysis
        if score >= 0.85 and min_events >= 20 and num_sessions >= 2:
            return "HIGH"
        elif score >= 0.80 and min_events >= 15:
            return "HIGH"
        elif score >= 0.70 and min_events >= 10:
            return "MEDIUM"
        elif score >= 0.60 and min_events >= 6:
            return "MEDIUM"
        else:
            return "LOW"
    
    def print_correlation_update(self) -> str:
        """
        Generate a compact status table showing current attack progress.
        Called after each send command to display real-time correlation results.
        """
        correlated_flows = self.perform_cumulative_correlation_attack()
        
        report = []
        report.append("\n" + "=" * 80)
        report.append("CORRELATION ATTACK STATUS")
        report.append("=" * 80)
        
        if not correlated_flows:
            report.append("\n📊 No correlations detected yet. Continue sending traffic...")
            report.append("=" * 80)
            return "\n".join(report)
        
        # Summary statistics
        high_conf = [f for f in correlated_flows if f['confidence'] == 'HIGH']
        med_conf = [f for f in correlated_flows if f['confidence'] == 'MEDIUM']
        low_conf = [f for f in correlated_flows if f['confidence'] == 'LOW']
        
        report.append(f"\n📈 Total Circuits Detected: {len(correlated_flows)} "
                    f"(🟢 {len(high_conf)} HIGH, 🟡 {len(med_conf)} MEDIUM, 🔴 {len(low_conf)} LOW)")
        
        # Table header
        report.append("\n┌────────────────────────────────────┬──────────────┬──────────┬──────────┐")
        report.append("│ Circuit                            │ Confidence   │ Score    │ Logs     │")
        report.append("├────────────────────────────────────┼──────────────┼──────────┼──────────┤")
        
        # Table rows
        for flow in correlated_flows:
            circuit = f"{flow['entry_node'][:8]} → {flow['exit_node'][:8]}"
            score = flow['correlation_score']
            confidence = flow['confidence']
            
            # Calculate total messages (normalized)
            total_messages = (flow['entry_events'] + flow['exit_events']) / 6
            
            # Confidence indicator
            if confidence == 'HIGH':
                conf_indicator = '🟢 HIGH'
            elif confidence == 'MEDIUM':
                conf_indicator = '🟡 MED '
            else:
                conf_indicator = '🔴 LOW '
            
            report.append(f"│ {circuit:<34} │ {conf_indicator:^11} │ {score:>7.1%}  │ {total_messages:^8.0f} │")
        
        report.append("└────────────────────────────────────┴──────────────┴──────────┴──────────┘")
        
        # Status message
        if high_conf:
            report.append(f"\n✅ ATTACK SUCCESS: {len(high_conf)} circuit(s) deanonymized with high confidence!")
        elif med_conf:
            report.append(f"\n⚠️  IN PROGRESS: {len(med_conf)} circuit(s) showing correlation. Continue sending traffic...")
        else:
            report.append("\n⏳ MONITORING: Low confidence. More data needed for deanonymization.")
        
        report.append("=" * 80)

        return "\n".join(report)
    
    def get_deanonymized_circuits(self) -> List[Dict]:
        """
        Return only successfully deanonymized circuits (high confidence).
        
        Returns:
            List of circuits with HIGH confidence correlations
        """
        all_flows = self.perform_cumulative_correlation_attack()
        return [flow for flow in all_flows if flow['confidence'] == 'HIGH']
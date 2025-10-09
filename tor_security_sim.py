import time
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
import statistics

class CorrelationAttackAnalyzer:
    """
    Performs timing correlation attacks on Tor networks by analyzing
    timestamp patterns from compromised nodes.
    """
    
    def __init__(self, compromised_nodes: List, time_window: float = 2.0, 
                 correlation_threshold: float = 0.7):
        """
        Initialize the correlation attack analyzer.
        
        Args:
            compromised_nodes: List of compromised Node objects
            time_window: Time window in seconds for correlating events (default: 2.0s)
            correlation_threshold: Minimum correlation score to link flows (0-1)
        """
        self.compromised_nodes = compromised_nodes
        self.time_window = time_window
        self.correlation_threshold = correlation_threshold
        
        # Separate entry and exit nodes
        self.entry_nodes = [node for node in compromised_nodes if node.type == "guard"]
        self.exit_nodes = [node for node in compromised_nodes if node.type == "exit"]
        self.middle_nodes = [node for node in compromised_nodes if node.type == "relay"]
        
    def collect_timing_data(self) -> Dict[str, List[float]]:
        """
        Collect timing data from all compromised nodes.
        
        Returns:
            Dictionary mapping node_id to list of timestamps
        """
        timing_data = {}
        for node in self.compromised_nodes:
            timing_data[node.id] = node.timing_data.copy()
        return timing_data
    
    def _create_time_series(self, timestamps: List[float]) -> List[Tuple[float, int]]:
        """
        Convert raw timestamps into a time series of event counts per interval.
        
        Args:
            timestamps: List of raw timestamps
            
        Returns:
            List of (time_bucket, event_count) tuples
        """
        if not timestamps:
            return []
        
        # Sort timestamps
        sorted_times = sorted(timestamps)
        
        # Create time buckets (100ms intervals for granularity)
        bucket_size = 0.1
        min_time = sorted_times[0]
        max_time = sorted_times[-1]
        
        # Count events per bucket
        buckets = defaultdict(int)
        for ts in sorted_times:
            bucket = int((ts - min_time) / bucket_size)
            buckets[bucket] += 1
        
        # Convert to time series
        time_series = [(min_time + bucket * bucket_size, count) 
                       for bucket, count in sorted(buckets.items())]
        
        return time_series
    
    def _calculate_correlation_score(self, entry_times: List[float], 
                                     exit_times: List[float]) -> float:
        """
        Calculate correlation score between entry and exit timing patterns.
        Uses a bidirectional matching approach with penalties.
        
        Algorithm:
        1. For each entry event, find the closest exit event within time_window
        2. Each exit event can only be matched once (greedy matching)
        3. Calculate base score as: (matched_events) / (total_events)
        4. Apply balance penalty if one side has many more events than the other
        
        Args:
            entry_times: Timestamps from entry node
            exit_times: Timestamps from exit node
            
        Returns:
            Correlation score between 0 and 1
        """
        if not entry_times or not exit_times:
            return 0.0
        
        # Create time series for both
        entry_series = self._create_time_series(entry_times)
        exit_series = self._create_time_series(exit_times)
        
        if not entry_series or not exit_series:
            return 0.0
        
        # Find overlapping time window
        entry_start = entry_series[0][0]
        entry_end = entry_series[-1][0]
        exit_start = exit_series[0][0]
        exit_end = exit_series[-1][0]
        
        # Check for temporal overlap (accounting for network delay)
        max_delay = 1.0  # Maximum expected Tor network delay in seconds
        
        if exit_start > entry_end + max_delay or entry_start > exit_end + max_delay:
            return 0.0  # No temporal overlap
        
        # Bidirectional matching with penalties
        entry_matched = 0
        used_exits = set()
        
        # Match entry events to exit events (greedy: find closest match)
        for entry_time in entry_times:
            best_match = None
            best_distance = float('inf')
            
            # Find the closest unused exit event within the time window
            for i, exit_time in enumerate(exit_times):
                if i in used_exits:
                    continue  # This exit was already matched
                    
                distance = abs(exit_time - entry_time)
                
                if distance <= self.time_window and distance < best_distance:
                    best_match = i
                    best_distance = distance
            
            if best_match is not None:
                entry_matched += 1
                used_exits.add(best_match)  # Mark this exit as used
        
        # Count how many exit events got matched
        exit_matched = len(used_exits)
        
        # Calculate score considering both directions
        total_events = len(entry_times) + len(exit_times)
        matched_events = entry_matched + exit_matched
        
        # Base correlation score: how many events were successfully paired
        base_score = matched_events / total_events if total_events > 0 else 0.0
        
        # Penalty for imbalanced matching
        entry_ratio = entry_matched / len(entry_times) if len(entry_times) > 0 else 0.0
        exit_ratio = exit_matched / len(exit_times) if len(exit_times) > 0 else 0.0
        balance_factor = min(entry_ratio, exit_ratio) / max(entry_ratio, exit_ratio) if max(entry_ratio, exit_ratio) > 0 else 0.0
        
        # Final score with balance consideration
        # 70% weight on base score, 30% on balance
        correlation = base_score * (0.7 + 0.3 * balance_factor)
        
        return min(correlation, 1.0)
    
    def _find_session_boundaries(self, timestamps: List[float], 
                                 gap_threshold: float = 5.0) -> List[Tuple[float, float]]:
        """
        Identify distinct sessions based on gaps in activity.
        
        Args:
            timestamps: List of timestamps
            gap_threshold: Minimum gap in seconds to consider a new session
            
        Returns:
            List of (session_start, session_end) tuples
        """
        if not timestamps:
            return []
        
        sorted_times = sorted(timestamps)
        sessions = []
        session_start = sorted_times[0]
        
        for i in range(1, len(sorted_times)):
            gap = sorted_times[i] - sorted_times[i-1]
            if gap > gap_threshold:
                # End current session
                sessions.append((session_start, sorted_times[i-1]))
                # Start new session
                session_start = sorted_times[i]
        
        # Add final session
        sessions.append((session_start, sorted_times[-1]))
        
        return sessions
    
    def get_timing_statistics(self) -> Dict:
        """
        Get statistical analysis of timing patterns.
        
        Returns:
            Dictionary with timing statistics
        """
        timing_data = self.collect_timing_data()
        stats = {}
        
        for node_id, timestamps in timing_data.items():
            if len(timestamps) < 2:
                continue
                
            sorted_times = sorted(timestamps)
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
        """Calculate confidence for individual sessions."""
        min_events = min(entry_events, exit_events)
        
        if correlation_score >= 0.85 and min_events >= 15:
            return "HIGH"
        elif correlation_score >= 0.65 and min_events >= 8:
            return "MEDIUM"
        else:
            return "LOW"
    
    def perform_correlation_attack(self) -> List[Dict]:
        """
        Execute the timing correlation attack to link entry and exit traffic.
        
        Returns:
            List of correlated flows with their metadata
        """
        timing_data = self.collect_timing_data()
        correlated_flows = []
        
        # Remove duplicate nodes by ID
        unique_entry_nodes = list({node.id: node for node in self.entry_nodes}.values())
        unique_exit_nodes = list({node.id: node for node in self.exit_nodes}.values())
        
        # Analyze each entry node
        for entry_node in unique_entry_nodes:
            entry_times = timing_data.get(entry_node.id, [])
            if not entry_times:
                continue
            
            entry_sessions = self._find_session_boundaries(entry_times)
            
            # Try to correlate with each exit node
            for exit_node in unique_exit_nodes:
                exit_times = timing_data.get(exit_node.id, [])
                if not exit_times:
                    continue
                
                exit_sessions = self._find_session_boundaries(exit_times)
                
                # Correlate each entry session with exit sessions
                for entry_start, entry_end in entry_sessions:
                    entry_session_times = [t for t in entry_times 
                                          if entry_start <= t <= entry_end]
                    
                    for exit_start, exit_end in exit_sessions:
                        exit_session_times = [t for t in exit_times 
                                             if exit_start <= t <= exit_end]
                        
                        # Calculate correlation
                        score = self._calculate_correlation_score(
                            entry_session_times, exit_session_times
                        )
                        
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
        
        # Deduplication
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
        Execute correlation attack with cumulative scoring across all sessions
        for the same circuit. This builds confidence over time as more traffic
        is observed through the same entry-exit pair.
        
        Returns:
            List of correlated flows with cumulative metrics
        """
        timing_data = self.collect_timing_data()
        
        # Deduplicate nodes
        unique_entry_nodes = list({node.id: node for node in self.entry_nodes}.values())
        unique_exit_nodes = list({node.id: node for node in self.exit_nodes}.values())
        
        # Store all session data per circuit
        circuit_sessions = {}
        
        # Analyze each entry-exit pair
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
                        
                        # Collect ALL sessions above minimum threshold
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
            
            # Combine all timing data across sessions
            all_entry_times = []
            all_exit_times = []
            total_entry_events = 0
            total_exit_events = 0
            
            for session in sessions:
                all_entry_times.extend(session['entry_times'])
                all_exit_times.extend(session['exit_times'])
                total_entry_events += session['entry_events']
                total_exit_events += session['exit_events']
            
            # Calculate cumulative correlation score
            cumulative_score = self._calculate_correlation_score(
                all_entry_times, all_exit_times
            )
            
            # Calculate session consistency bonus
            session_scores = [s['individual_score'] for s in sessions]
            avg_session_score = statistics.mean(session_scores)
            score_consistency = 1.0 - statistics.stdev(session_scores) if len(session_scores) > 1 else 1.0
            
            # Bonus for multiple consistent sessions
            session_bonus = min(0.1 * (len(sessions) - 1), 0.3)  # Up to 30% bonus
            consistency_bonus = 0.05 * score_consistency  # Up to 5% bonus
            
            # Final cumulative score
            final_score = min(cumulative_score + session_bonus + consistency_bonus, 1.0)
            
            # Calculate cumulative confidence
            cumulative_confidence = self._calculate_cumulative_confidence(
                final_score, total_entry_events, total_exit_events, len(sessions)
            )
            
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
        
        # Sort by final score
        correlated_flows.sort(key=lambda x: x['correlation_score'], reverse=True)
        
        return correlated_flows
    
    def _calculate_cumulative_confidence(self, score: float, entry_events: int, 
                                        exit_events: int, num_sessions: int) -> str:
        """
        Calculate confidence level based on cumulative evidence.
        More sessions and events increase confidence.
        """
        min_events = min(entry_events, exit_events)
        
        # Adjusted thresholds considering cumulative data
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
        Generate a compact correlation update table showing current attack status.
        Called after each send command to show progress.
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
        
        # Summary stats
        high_conf = [f for f in correlated_flows if f['confidence'] == 'HIGH']
        med_conf = [f for f in correlated_flows if f['confidence'] == 'MEDIUM']
        low_conf = [f for f in correlated_flows if f['confidence'] == 'LOW']
        
        report.append(f"\n📈 Total Circuits Detected: {len(correlated_flows)} "
                    f"(🟢 {len(high_conf)} HIGH, 🟡 {len(med_conf)} MEDIUM, 🔴 {len(low_conf)} LOW)")
        
        # Table header (renamed “Sessions” → “Messages”)
        report.append("\n┌────────────────────────────────────┬──────────────┬──────────┬──────────┐")
        report.append("│ Circuit                            │ Confidence   │ Score    │ Messages │")
        report.append("├────────────────────────────────────┼──────────────┼──────────┼──────────┤")
        
        # Table rows
        for flow in correlated_flows:
            circuit = f"{flow['entry_node'][:8]} → {flow['exit_node'][:8]}"
            score = flow['correlation_score']
            confidence = flow['confidence']
            
            # Use total number of messages (sum of entry + exit events)
            total_messages = flow['entry_events'] + flow['exit_events']
            
            # Confidence indicator
            if confidence == 'HIGH':
                conf_indicator = '🟢 HIGH'
            elif confidence == 'MEDIUM':
                conf_indicator = '🟡 MED '
            else:
                conf_indicator = '🔴 LOW '
            
            report.append(f"│ {circuit:<34} │ {conf_indicator:^11} │ {score:>7.1%}  │ {total_messages:^8} │")
        
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
        Return only high-confidence deanonymized circuits.
        
        Returns:
            List of circuits that have been successfully deanonymized
        """
        all_flows = self.perform_cumulative_correlation_attack()
        return [flow for flow in all_flows if flow['confidence'] == 'HIGH']
    

        
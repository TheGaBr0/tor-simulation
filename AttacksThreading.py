import threading
from queue import Queue
from typing import List, Dict, Optional
import time


class ThreadedCorrelationAnalyzer:
    """
    Threaded wrapper for CorrelationAttackAnalyzer to run analysis tasks concurrently.
    """
    
    def __init__(self, analyzer):
        """
        Initialize with an existing CorrelationAttackAnalyzer instance.
        
        Args:
            analyzer: CorrelationAttackAnalyzer instance
        """
        self.analyzer = analyzer
        self.results = {
            'report': None,
            'deanonymized': None,
            'compromised_info': None,
            'errors': []
        }
        self.threads = []
        self.lock = threading.Lock()
        
    def _generate_report_thread(self):
        """Thread for generating cumulative attack report"""
        try:
            print("[Thread-Report] Generating cumulative attack report...")
            start = time.time()
            report = self.analyzer.generate_cumulative_attack_report()
            elapsed = time.time() - start
            
            with self.lock:
                self.results['report'] = report
            
            print(f"[Thread-Report] ✓ Report generated in {elapsed:.2f}s")
        except Exception as e:
            error_msg = f"Report generation failed: {str(e)}"
            print(f"[Thread-Report] ✗ {error_msg}")
            with self.lock:
                self.results['errors'].append(error_msg)
    
    def _get_deanonymized_thread(self):
        """Thread for getting deanonymized circuits"""
        try:
            print("[Thread-Deanonymized] Analyzing deanonymized circuits...")
            start = time.time()
            deanonymized = self.analyzer.get_deanonymized_circuits()
            elapsed = time.time() - start
            
            with self.lock:
                self.results['deanonymized'] = deanonymized
            
            print(f"[Thread-Deanonymized] ✓ Found {len(deanonymized)} high-confidence circuits in {elapsed:.2f}s")
        except Exception as e:
            error_msg = f"Deanonymization analysis failed: {str(e)}"
            print(f"[Thread-Deanonymized] ✗ {error_msg}")
            with self.lock:
                self.results['errors'].append(error_msg)
    
    def _get_compromised_info_thread(self):
        """Thread for getting compromised node info"""
        try:
            print("[Thread-NodeInfo] Generating circuit routes for compromised nodes...")
            start = time.time()
            self.analyzer.get_info_compromised_nodes()
            elapsed = time.time() - start
            
            with self.lock:
                self.results['compromised_info'] = True
            
            print(f"[Thread-NodeInfo] ✓ Circuit routes generated for {len(self.analyzer.compromised_nodes)} nodes in {elapsed:.2f}s")
        except Exception as e:
            error_msg = f"Node info retrieval failed: {str(e)}"
            print(f"[Thread-NodeInfo] ✗ {error_msg}")
            with self.lock:
                self.results['errors'].append(error_msg)
    
    def run_threaded_analysis(self, include_report: bool = True, 
                            include_deanonymized: bool = True,
                            include_node_info: bool = True) -> Dict:
        """
        Run correlation analysis with threading.
        
        Args:
            include_report: Generate cumulative attack report
            include_deanonymized: Get deanonymized circuits
            include_node_info: Generate circuit routes for compromised nodes
            
        Returns:
            Dictionary containing all results
        """
        print("\n" + "=" * 80)
        print("STARTING THREADED CORRELATION ATTACK ANALYSIS")
        print("=" * 80)
        
        start_time = time.time()
        self.threads = []
        
        # Create threads based on requested analyses
        if include_report:
            report_thread = threading.Thread(
                target=self._generate_report_thread,
                name="ReportThread",
                daemon=True
            )
            self.threads.append(report_thread)
        
        if include_deanonymized:
            deanon_thread = threading.Thread(
                target=self._get_deanonymized_thread,
                name="DeanonymizedThread",
                daemon=True
            )
            self.threads.append(deanon_thread)
        
        if include_node_info:
            nodeinfo_thread = threading.Thread(
                target=self._get_compromised_info_thread,
                name="NodeInfoThread",
                daemon=True
            )
            self.threads.append(nodeinfo_thread)
        
        # Start all threads
        print(f"\nStarting {len(self.threads)} analysis thread(s)...\n")
        for thread in self.threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in self.threads:
            thread.join()
        
        elapsed = time.time() - start_time
        
        print("\n" + "=" * 80)
        print(f"ANALYSIS COMPLETE - Total time: {elapsed:.2f}s")
        print("=" * 80)
        
        # Print any errors
        if self.results['errors']:
            print("\n⚠️  ERRORS ENCOUNTERED:")
            for error in self.results['errors']:
                print(f"  - {error}")
        
        return self.results
    
    def print_report(self):
        """Print the generated report if available"""
        if self.results['report']:
            print("\n" + self.results['report'])
        else:
            print("\n⚠️  No report available. Run analysis first or check for errors.")
    
    def get_deanonymized_summary(self) -> Optional[str]:
        """Get a summary of deanonymized circuits"""
        if not self.results['deanonymized']:
            return None
        
        circuits = self.results['deanonymized']
        summary = ["\n" + "=" * 80]
        summary.append("DEANONYMIZED CIRCUITS SUMMARY")
        summary.append("=" * 80)
        summary.append(f"\nTotal High-Confidence Circuits: {len(circuits)}\n")
        
        for i, circuit in enumerate(circuits, 1):
            summary.append(f"\n{i}. {circuit['entry_node']} → {circuit['exit_node']}")
            summary.append(f"   Confidence: {circuit['confidence']}")
            summary.append(f"   Correlation Score: {circuit['correlation_score']:.1%}")
            summary.append(f"   Sessions: {circuit['num_sessions']}")
            summary.append(f"   Total Events: {circuit['entry_events']} → {circuit['exit_events']}")
        
        summary.append("\n" + "=" * 80)
        return "\n".join(summary)


# Example usage function
def run_threaded_correlation_attack(compromised_nodes: List, 
                                   time_window: float = 10.0,
                                   correlation_threshold: float = 0.75) -> Dict:
    """
    Convenience function to run threaded correlation attack analysis.
    
    Args:
        compromised_nodes: List of compromised Node objects
        time_window: Time window for correlation (default: 10.0s)
        correlation_threshold: Minimum correlation threshold (default: 0.75)
        
    Returns:
        Dictionary with all analysis results
    """
    # Import here to avoid circular dependencies
    
    # Create analyzer
    analyzer = CorrelationAttackAnalyzer(
        compromised_nodes=compromised_nodes,
        time_window=time_window,
        correlation_threshold=correlation_threshold
    )
    
    # Create threaded wrapper
    threaded_analyzer = ThreadedCorrelationAnalyzer(analyzer)
    
    # Run analysis
    results = threaded_analyzer.run_threaded_analysis()
    
    # Print report if available
    threaded_analyzer.print_report()
    
    # Print deanonymized summary
    summary = threaded_analyzer.get_deanonymized_summary()
    if summary:
        print(summary)
    
    return results



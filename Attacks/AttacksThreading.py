import threading
from queue import Queue
from typing import List, Dict, Optional
import time


class ThreadedCorrelationAnalyzer:
    """
    Multi-threaded wrapper for correlation attack analysis.
    Executes multiple analysis tasks concurrently to improve performance
    when processing large amounts of timing data.
    """
    
    def __init__(self, analyzer):
        """
        Initialize the threaded analyzer wrapper.
        
        Args:
            analyzer: CorrelationAttackAnalyzer instance to run analysis on
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
        """
        Worker thread for generating cumulative attack report.
        Executes in parallel with other analysis tasks.
        """
        try:
            print("[Thread-Report] Generating cumulative attack report...")
            start = time.time()
            report = self.analyzer.generate_cumulative_attack_report()
            elapsed = time.time() - start
            
            # Thread-safe result storage
            with self.lock:
                self.results['report'] = report
            
            print(f"[Thread-Report] ✓ Report generated in {elapsed:.2f}s")
        except Exception as e:
            error_msg = f"Report generation failed: {str(e)}"
            print(f"[Thread-Report] ✗ {error_msg}")
            with self.lock:
                self.results['errors'].append(error_msg)
    
    def _get_deanonymized_thread(self):
        """
        Worker thread for identifying deanonymized circuits.
        Filters and returns only high-confidence correlations.
        """
        try:
            print("[Thread-Deanonymized] Analyzing deanonymized circuits...")
            start = time.time()
            deanonymized = self.analyzer.get_deanonymized_circuits()
            elapsed = time.time() - start
            
            # Thread-safe result storage
            with self.lock:
                self.results['deanonymized'] = deanonymized
            
            print(f"[Thread-Deanonymized] ✓ Found {len(deanonymized)} high-confidence circuits in {elapsed:.2f}s")
        except Exception as e:
            error_msg = f"Deanonymization analysis failed: {str(e)}"
            print(f"[Thread-Deanonymized] ✗ {error_msg}")
            with self.lock:
                self.results['errors'].append(error_msg)
    
    def _get_compromised_info_thread(self):
        """
        Worker thread for generating circuit route information.
        Collects and displays routing data for all compromised nodes.
        """
        try:
            print("[Thread-NodeInfo] Generating circuit routes for compromised nodes...")
            start = time.time()
            self.analyzer.get_info_compromised_nodes()
            elapsed = time.time() - start
            
            # Thread-safe result storage
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
        Execute correlation analysis using multiple threads for parallel processing.
        Significantly reduces analysis time when multiple tasks are requested.
        """
        print("\n" + "=" * 80)
        print("STARTING THREADED CORRELATION ATTACK ANALYSIS")
        print("=" * 80)
        
        start_time = time.time()
        self.threads = []
        
        # Create worker threads based on requested analyses
        if include_report:
            report_thread = threading.Thread(
                target=self._generate_report_thread,
                name="ReportThread",
                daemon=True  # Thread terminates when main program exits
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
        
        # Launch all threads
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
        
        # Report any errors that occurred
        if self.results['errors']:
            print("\n⚠️  ERRORS ENCOUNTERED:")
            for error in self.results['errors']:
                print(f"  - {error}")
        
        return self.results
    
    def print_report(self):
        """
        Display the generated correlation attack report.
        Must be called after run_threaded_analysis() completes.
        """
        if self.results['report']:
            print("\n" + self.results['report'])
        else:
            print("\n⚠️  No report available. Run analysis first or check for errors.")
    
    def get_deanonymized_summary(self) -> Optional[str]:
        """
        Generate a formatted summary of successfully deanonymized circuits.
        """
        if not self.results['deanonymized']:
            return None
        
        circuits = self.results['deanonymized']
        summary = ["\n" + "=" * 80]
        summary.append("DEANONYMIZED CIRCUITS SUMMARY")
        summary.append("=" * 80)
        summary.append(f"\nTotal High-Confidence Circuits: {len(circuits)}\n")
        
        # List each deanonymized circuit with key metrics
        for i, circuit in enumerate(circuits, 1):
            summary.append(f"\n{i}. {circuit['entry_node']} → {circuit['exit_node']}")
            summary.append(f"   Confidence: {circuit['confidence']}")
            summary.append(f"   Correlation Score: {circuit['correlation_score']:.1%}")
            summary.append(f"   Sessions: {circuit['num_sessions']}")
            summary.append(f"   Total Events: {circuit['entry_events']} → {circuit['exit_events']}")
        
        summary.append("\n" + "=" * 80)
        return "\n".join(summary)
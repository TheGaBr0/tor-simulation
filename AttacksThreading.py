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
    



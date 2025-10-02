import random
import statistics
import time
from typing import List, Dict, Optional
# from Node import *   # keep your Node class import as you had it

class SecurityTest:
    def __init__(self, nodes: List, compromision_rate: int):
        self.nodes = nodes
        self.compromision_rate = compromision_rate
        self.compromised_nodes: List[str] = []
        self.circuits_created: List[Dict] = []   # start empty list

        # Data collection structures for attacks
        self.timing_data: Dict[str, List[float]] = {}   # node_id -> [timestamps]
        self.packet_sizes: Dict[str, List[int]] = {}    # node_id -> [packet sizes]

    def compromise(self):
         for node in self.nodes:
            if random.random() < (self.compromision_rate / 100):
                  node.compromised = True

    def create_circuit(self,
                       circuit_id: str,
                       guard,
                       middle_list: Optional[List] = None,
                       exit_node = None,
                       guard_comp: bool = False,
                       middle_list_comp: Optional[List[bool]] = None,
                       exit_comp: bool = False) -> Dict:
      
        middle_list = middle_list or []
        # default compromised flags to False for each middle node if not provided
        if middle_list_comp is None:
            middle_list_comp = [False] * len(middle_list)

        if len(middle_list_comp) != len(middle_list):
            raise ValueError("middle_list_comp must have same length as middle_list")

        circuit = {
            'circuit_id': circuit_id,
            'guard': guard,
            'middle_list': middle_list,
            'exit': exit_node,
            'guard_compromised': bool(guard_comp),
            'middle_compromised_list': middle_list_comp,
            'exit_compromised': bool(exit_comp)
        }
        return circuit

    def extract_circuit(self, circuit_id: str) -> Optional[Dict]:
        """Return the circuit dict for circuit_id or None if not found."""
        for c in self.circuits_created:
            if c.get('circuit_id') == circuit_id:
                return c
        return None

    def find_circuits_with_node(self, node_id: str) -> List[Dict]:
        """Return all circuits that include node_id (guard, any middle, or exit)."""
        found = []
        for c in self.circuits_created:
            # check guard
            guard = c.get('guard')
            if guard and getattr(guard, 'id', guard) == node_id:
                found.append(c)
                continue
            # check exit
            exit_n = c.get('exit')
            if exit_n and getattr(exit_n, 'id', exit_n) == node_id:
                found.append(c)
                continue
            # check middle list
            for m in c.get('middle_list', []):
                if getattr(m, 'id', m) == node_id:
                    found.append(c)
                    break
        return found

    def extract_all_circuits(self) -> List[Dict]:
        """Return all circuits (shallow copy)."""
        return list(self.circuits_created)


    def network_analysis(self):
        """Analyze the network and randomly compromise nodes based on compromision_rate.
           Initializes timing/packet data for compromised nodes.
        """
        self.compromised_nodes = []
        circid=0
        relay_nodes=[]
        relay_nodes_compromised=[]
        for node in self.nodes:
            if node.compromised:
                self.compromised_nodes.append(getattr(node, 'id', node))
                # Initialize data structures for this compromised node
                self.timing_data[getattr(node, 'id', node)] = []
                self.packet_sizes[getattr(node, 'id', node)] = []


            if node.compromised:
                   self.timing_data[node.id]=node.timing_data
            else: 
                    self.timing_data[node.id]=None

            if node.type=="guard":
                temp=self.create_circuit(circid,node,None,None,node.compromised,None,False)
            elif node.type=="relay":
               relay_nodes.append(node)
               relay_nodes_compromised.append(node.compromised)
            elif node.type=="exit":
                temp["middle_list"]=relay_nodes
                temp["exit"]=node
                temp["middle_compromised_list"]=relay_nodes_compromised
                temp["exit_compromised"]=node.compromised
                self.circuits_created.append(temp)
                circid=circid+1



        # Example: optionally create some circuits from current guards (not required).
        # Y ou can call build_random_circuit externally as needed.

        print(
            f"Network Status:\n"
            f"Total nodes: {len(self.nodes)}\n"
            f"Compromised nodes: {len(self.compromised_nodes)}\n"
            f"Compromise probability: {(len(self.compromised_nodes) / len(self.nodes) * 100):.1f}%"
        )


    def correlation_attack(self) -> Dict:
        """Detect circuits where both guard and exit (or replacements) are compromised.
        If guard or exit are not compromised/available, use the first compromised
        middle as guard replacement and the last compromised middle as exit replacement.
        """
        print("\n=== ATTACK 1: End-to-End Correlation Attack (with middle-node fallbacks) ===")

        vulnerable_circuits = []
        correlation_scores = []

        def get_node_id(node_or_id):
            """Return node id whether item is node object or raw id."""
            if node_or_id is None:
                return None
            return getattr(node_or_id, "id", node_or_id)

        for circuit in self.circuits_created:
            # skip invalid/empty entries
            if not isinstance(circuit, dict):
                continue

            guard_comp = circuit.get('guard_compromised', False)
            exit_comp = circuit.get('exit_compromised', False)

            guard = circuit.get('guard')
            exit_node = circuit.get('exit')

            guard_id = get_node_id(guard)
            exit_id = get_node_id(exit_node)

            middle_list = circuit.get('middle_list') or []
            middle_comp_flags = circuit.get('middle_compromised_list') or []

            # Helper: find first compromised middle (closest to guard/top),
            # and last compromised middle (closest to exit/bottom)
            first_comp_middle_id = None
            last_comp_middle_id = None

            # Ensure lengths match - if not, derive compromise from flags if possible
            for i, m in enumerate(middle_list):
                mid_id = get_node_id(m)
                flag = False
                if i < len(middle_comp_flags):
                    flag = bool(middle_comp_flags[i])
                # If flags don't exist, also check global compromised list or node attribute:
                if not flag:
                    # try to check node attribute if it is an object and has .compromised
                    if hasattr(m, 'compromised'):
                        flag = bool(getattr(m, 'compromised', False))
                    else:
                        # fallback: check if mid_id appears in global compromised_nodes list
                        flag = mid_id in getattr(self, "compromised_nodes", [])

                if flag:
                    if first_comp_middle_id is None:
                        first_comp_middle_id = mid_id
                    last_comp_middle_id = mid_id

            # Choose effective guard/exit IDs:
            effective_guard_id = guard_id if guard_comp and guard_id is not None else first_comp_middle_id
            effective_exit_id = exit_id if exit_comp and exit_id is not None else last_comp_middle_id

            # If still missing one side, skip this circuit
            if effective_guard_id is None or effective_exit_id is None:
                continue

            # Pull timing traces (lists of timestamps) from self.timing_data
            guard_times = self.timing_data.get(effective_guard_id, [])
            exit_times = self.timing_data.get(effective_exit_id, [])

            # require at least two timestamps on each side to compute deltas
            if len(guard_times) >= 2 and len(exit_times) >= 2:
                guard_deltas = [guard_times[i+1] - guard_times[i] for i in range(len(guard_times)-1)]
                exit_deltas = [exit_times[i+1] - exit_times[i] for i in range(len(exit_times)-1)]

                if guard_deltas and exit_deltas:
                    # Simple similarity metric: 1 - clipped absolute diff of means
                    mean_diff = abs(statistics.mean(guard_deltas) - statistics.mean(exit_deltas))
                    correlation = 1 - min(mean_diff, 1.0)   # maps diff 0 -> 1, diff>=1 -> 0
                    correlation = max(0.0, min(1.0, correlation))

                    correlation_scores.append(correlation)
                    vulnerable_circuits.append({
                        'circuit_id': circuit.get('circuit_id'),
                        'guard': effective_guard_id,
                        'exit': effective_exit_id,
                        'original_guard': guard_id,
                        'original_exit': exit_id,
                        'used_guard_replacement': (effective_guard_id != guard_id),
                        'used_exit_replacement': (effective_exit_id != exit_id),
                        'correlation_score': f"{correlation:.3f}",
                        'severity': 'CRITICAL' if correlation > 0.8 else ('HIGH' if correlation > 0.5 else 'MEDIUM')
                    })

        total = len(self.circuits_created) if self.circuits_created else 0
        avg_correlation = statistics.mean(correlation_scores) if correlation_scores else 0.0
        effectiveness = (len(vulnerable_circuits) / total * 100) if total else 0.0

        result = {
            'attack_type': 'End-to-End Correlation (with middle fallbacks)',
            'vulnerable_circuits': len(vulnerable_circuits),
            'total_circuits': total,
            'average_correlation': f"{avg_correlation:.3f}",
            'details': vulnerable_circuits[:5],
            'effectiveness': f"{effectiveness:.1f}%"
        }

        print("\nResults:")
        print(f"  Vulnerable circuits: {result['vulnerable_circuits']}/{result['total_circuits']}")
        print(f"  Attack effectiveness: {result['effectiveness']}")
        print(f"  Average correlation score: {result['average_correlation']}")

        if vulnerable_circuits:
            ex = vulnerable_circuits[0]
            print(f"\n  Example vulnerable circuit:")
            print(f"    Circuit {ex['circuit_id']}: {ex['original_guard']} -> ... -> {ex['original_exit']}")
            print(f"    Used guard replacement? {ex['used_guard_replacement']}, used exit replacement? {ex['used_exit_replacement']}")
            print(f"    Effective mapping: {ex['guard']} -> ... -> {ex['exit']}")
            print(f"    Correlation: {ex['correlation_score']}")

        return result
    
    def circuit_building_attack(self):
          for node in self.nodes:
            if node.compromised and node.running:
                print(node.circuit_building_compromisation)



    
    
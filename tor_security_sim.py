import random
import statistics
import time
from typing import List, Dict, Optional, Tuple
import socket
from Node import *
# from Node import *   # keep your Node class import as you had it

class SecurityTest:
    def __init__(self):
        self.nodes = []
        self.compromision_rate = []
        self.compromised_nodes: List[str] = []
        self.circuits_created: List[Dict] = []   # start empty list
        self.circuits_Explored: List[List[
            Tuple[str, float, int, Tuple[str, int], int, Tuple[str, int]]
            ]] =[]

    def compromise(self):
         for node in self.nodes:
            if random.random() < (self.compromision_rate / 100):
                  node.compromised = True

    def create_circuit(self,
                       circuit_id: str,
                       guard,
                       times_guard:  Optional[List],
                       middle_list: Optional[List],
                       times_List: Optional[List[List]],
                       exit_node,
                       times_exit: Optional[List],
                       guard_comp: bool,
                       middle_list_comp: Optional[List[bool]],
                       exit_comp: bool,
                       analyzed:bool
                       ) -> Dict:
      
        middle_list = middle_list or []
        # default compromised flags to False for each middle node if not provided
        if middle_list_comp is None and times_List is None:
            middle_list_comp = [False] * len(middle_list)
            times_List=[None] * len(middle_list)

        if len(middle_list_comp) != len(middle_list):
            raise ValueError("middle_list_comp must have same length as middle_list")

        circuit = {
            'circuit_id': circuit_id,
            'guard': guard,
            "times_guard": times_guard,
            'middle_list': middle_list,
            'times_List':times_List,
            'exit': exit_node,
            'times_exit':times_exit,
            'guard_compromised': bool(guard_comp),
            'middle_compromised_list': middle_list_comp,
            'exit_compromised': bool(exit_comp),
            'analyzed': analyzed
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


    def network_analysis(self, nodes: List,circ_id):
        """Analyze the network and randomly compromise nodes based on compromision_rate.
           Initializes timing/packet data for compromised nodes.
        """
        self.nodes=nodes
        self.compromised_nodes = []
        relay_nodes=[]
        relay_nodes_compromised=[]
        relay_nodes_times=[[]]

        for node in self.nodes:
            if node.compromised:
                self.compromised_nodes.append(getattr(node, 'id', node))
                # Initialize data structures for this compromised node

            if node.type=="guard":
                if node.compromised:
                     temp=self.create_circuit(
                                circ_id,
                                node,
                                node.timing_data,
                                None,
                                None,
                                None,
                                None,
                                node.compromised,
                                None,
                                None,
                                False)
            elif node.type=="relay":
               relay_nodes.append(node)
               relay_nodes_compromised.append(node.compromised)
               relay_nodes_times.append(node.timing_data)
            elif node.type=="exit":
                temp["middle_list"]=relay_nodes.copy()
                temp['times_List']=relay_nodes_times.copy()
                temp["exit"]=node
                temp['times_exit']=node.timing_data
                temp["middle_compromised_list"]=relay_nodes_compromised.copy()
                temp["exit_compromised"]=node.compromised
                self.circuits_created.append(temp)
                relay_nodes.clear()
                relay_nodes_compromised.clear()
                relay_nodes_times.clear()
               

        print(
            f"Network Status:\n"
            f"Total nodes: {len(self.nodes)}\n"
            f"Compromised nodes: {len(self.compromised_nodes)}\n"
            f"Compromise probability: {(len(self.compromised_nodes) / len(self.nodes) * 100):.1f}%"
        )


    def correlation_attack(self):
        print("\n=== ATTACK 1: End-to-End Correlation Attack (with middle-node fallbacks using circuit times) ===")

        vulnerable_circuits = []
        correlation_scores = []

        def get_node_id(node_or_id):
            """Return node id whether item is node object or raw id."""
            if node_or_id is None:
                return None
            return getattr(node_or_id, "id", node_or_id)
        
        def print_circuit_info(circuit):
            for entry in circuit: 
                print(f"{entry}:{circuit.get(entry)}")
               

        for circuit in self.circuits_created:
            #if  circuit.get("analyzed"):
            #    print_circuit_info(circuit)
            #    continue
            if not isinstance(circuit, dict):
                print("Skipping non-dict circuit entry.")
                continue

            circuit_id = circuit.get('circuit_id', '<no-id>')
            guard_comp = circuit.get('guard_compromised', False)
            exit_comp = circuit.get('exit_compromised', False)

            guard = circuit.get('guard')
            exit_node = circuit.get('exit')

            guard_id = get_node_id(guard)
            exit_id = get_node_id(exit_node)

            times_guard = circuit.get('times_guard')
            times_exit = circuit.get('times_exit')
            times_List = circuit.get('times_List') or []

            middle_list = circuit.get('middle_list') or []
            middle_comp_flags = circuit.get('middle_compromised_list') or []

            first_comp_middle_idx = None
            last_comp_middle_idx = None

            for i, m in enumerate(middle_list):
                flag = False
                if i < len(middle_comp_flags):
                    flag = bool(middle_comp_flags[i])
                if not flag and hasattr(m, 'compromised'):
                    flag = bool(getattr(m, 'compromised', False))
                elif not flag:
                    mid_id = get_node_id(m)
                    flag = mid_id in getattr(self, "compromised_nodes", [])

                if flag:
                    if first_comp_middle_idx is None:
                        first_comp_middle_idx = i
                    last_comp_middle_idx = i

            effective_guard_id = guard_id if guard_comp and guard_id is not None else (
                get_node_id(middle_list[first_comp_middle_idx]) if first_comp_middle_idx is not None else None
            )
            effective_exit_id = exit_id if exit_comp and exit_id is not None else (
                get_node_id(middle_list[last_comp_middle_idx]) if last_comp_middle_idx is not None else None
            )

            def pick_times_for_guard():
                if guard_comp and times_guard:
                    return times_guard, 'times_guard'
                if first_comp_middle_idx is not None and first_comp_middle_idx < len(times_List):
                    candidate = times_List[first_comp_middle_idx]
                    if candidate:
                        return candidate, f'times_List[{first_comp_middle_idx}]'
                return self.timing_data.get(effective_guard_id, []), 'timing_data'

            def pick_times_for_exit():
                if exit_comp and times_exit:
                    return times_exit, 'times_exit'
                if last_comp_middle_idx is not None and last_comp_middle_idx < len(times_List):
                    candidate = times_List[last_comp_middle_idx]
                    if candidate:
                        return candidate, f'times_List[{last_comp_middle_idx}]'
                return self.timing_data.get(effective_exit_id, []), 'timing_data'

            print("\n--- Circuit:", circuit_id, "---")
            print(f"  original_guard: {guard_id!s} (compromised={guard_comp})")
            print(f"  original_exit : {exit_id!s} (compromised={exit_comp})")
            print(f"  effective_guard: {effective_guard_id!s} (used_replacement={effective_guard_id != guard_id})")
            print(f"  effective_exit : {effective_exit_id!s} (used_replacement={effective_exit_id != exit_id})")

            if effective_guard_id is None or effective_exit_id is None:
                print("  SKIPPED: missing effective guard or exit (no compromised nodes available for either side).")
                continue

            guard_times, guard_times_source = pick_times_for_guard()
            exit_times, exit_times_source = pick_times_for_exit()

            guard_times = guard_times or []
            exit_times = exit_times or []

            def fmt_times_info(times, source):
                if not times:
                    return f"{source} -> empty"
                try:
                    return f"{source} -> n={len(times)}, first={times[0]}, last={times[-1]}"
                except Exception:
                    return f"{source} -> n={len(times)} (non-indexable contents)"

            print("  guard_times source/info:", fmt_times_info(guard_times, guard_times_source))
            print("  exit_times  source/info:", fmt_times_info(exit_times, exit_times_source))

            if len(guard_times) < 2 or len(exit_times) < 2:
                print("  SKIPPED: insufficient timestamps (need >=2 on both sides).")
                continue

            try:
                guard_deltas = [guard_times[i+1] - guard_times[i] for i in range(len(guard_times)-1)]
                exit_deltas = [exit_times[i+1] - exit_times[i] for i in range(len(exit_times)-1)]
            except Exception as e:
                print(f"  ERROR computing deltas: {e}")
                continue

            if not guard_deltas or not exit_deltas:
                print("  SKIPPED: empty deltas after computation.")
                continue

            mean_guard = statistics.mean(guard_deltas)
            mean_exit = statistics.mean(exit_deltas)
            mean_diff = abs(mean_guard - mean_exit)
            correlation = 1 - (mean_diff / max(mean_guard, mean_exit))
            correlation = max(0.0, min(1.0, correlation))

            severity = 'CRITICAL' if correlation > 0.8 else ('HIGH' if correlation > 0.5 else 'MEDIUM')

            correlation_scores.append(correlation)
            vulnerable_circuits.append({
                'circuit_id': circuit_id,
                'guard': effective_guard_id,
                'exit': effective_exit_id,
                'original_guard': guard_id,
                'original_exit': exit_id,
                'used_guard_replacement': (effective_guard_id != guard_id),
                'used_exit_replacement': (effective_exit_id != exit_id),
                'correlation_score': f"{correlation:.3f}",
                'severity': severity
            })

            print(f"  Computed: mean_guard_delta={mean_guard:.6f}, mean_exit_delta={mean_exit:.6f}")
            print(f"  mean_diff={mean_diff:.6f}, correlation={correlation:.3f}, severity={severity}")
            circuit["analyzed"]=True

        total = len(self.circuits_created) if self.circuits_created else 0
        avg_correlation = statistics.mean(correlation_scores) if correlation_scores else 0.0
        effectiveness = (len(vulnerable_circuits) / total * 100) if total else 0.0

        print("\n=== Summary ===")
        print(f"  Vulnerable circuits: {len(vulnerable_circuits)}/{total}")
        print(f"  Attack effectiveness: {effectiveness:.1f}%")
        print(f"  Average correlation score: {avg_correlation:.3f}")



    
    def circuit_building_attack(self):
        i=0
        for node in self.nodes:
            if node.compromised:
                for entry in node.RoutingEntry:
                    print(entry)


    def cellFlood_attack(self,node,ip,port):
        for nd in self.nodes:
              if node==nd.id and nd.compromised:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip,port))
                while 1:
                    x1, g_x1, g_x1_bytes_encrypted = process_dh_handshake_request(nd.pub)
                    create_cell = TorCell(circid=99, cmd=TorCommands.CREATE, data=encode_payload([g_x1_bytes_encrypted]))
                    sock.sendall(create_cell.to_bytes())
        



    
    
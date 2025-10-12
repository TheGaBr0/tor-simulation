from dataclasses import dataclass
from typing import List, Dict
from itertools import permutations


@dataclass
class Node:
    """
    Represents a Tor network node with its properties and compromise status.
    """
    id: str
    band_width: float
    uptime: float
    is_guard: bool = False
    is_exit: bool = False
    is_middle: bool = False
    compromised: bool = False


class Probabilities:
    """
    Calculates circuit selection probabilities and analyzes vulnerability
    to end-to-end correlation attacks in Tor networks.
    
    Implements bandwidth-weighted path selection as per Tor specification,
    then evaluates the probability that randomly constructed circuits will
    be compromised at both entry and exit points.
    """
    
    def __init__(self, bandwidth_weight: float = 0.95, uptime_weight: float = 0.05, 
                 num_middle_nodes: int = 1):
        """
        Initialize the probability calculator.
        """
        self.bandwidth_weight = bandwidth_weight
        self.uptime_weight = uptime_weight
        self.num_middle_nodes = num_middle_nodes
        self.guard_nodes: List[Node] = []
        self.middle_nodes: List[Node] = []
        self.exit_nodes: List[Node] = []

    def _calculate_node_probabilities(self, nodes: List[Node]) -> Dict[str, float]:
        """
        Calculate selection probability for each node based on weighted metrics.
        Tor preferentially selects high-bandwidth, high-uptime nodes.
        """
        if not nodes:
            return {}
        
        # Calculate weighted score for each node
        node_scores = {
            node.id: (node.band_width * self.bandwidth_weight + 
                     node.uptime * self.uptime_weight)
            for node in nodes
        }
        
        total_score = sum(node_scores.values())
        
        # Handle edge case of zero total score
        if total_score == 0:
            prob = 1.0 / len(nodes)
            return {node.id: prob for node in nodes}
        
        # Normalize to probabilities
        return {nid: score / total_score for nid, score in node_scores.items()}

    def set_nodes(self, guard_nodes: List[Node], middle_nodes: List[Node], 
                  exit_nodes: List[Node]):
        """
        Configure the network topology with available nodes at each position.
        """
        self.guard_nodes = guard_nodes
        self.middle_nodes = middle_nodes
        self.exit_nodes = exit_nodes

    def calculate_circuit_probability(self, guard_id: str, middle_ids: List[str], 
                                     exit_id: str) -> float:
        """
        Calculate the probability of a specific circuit being selected.
        Multiplies the independent selection probabilities of each node.
        """
        guard_probs = self._calculate_node_probabilities(self.guard_nodes)
        middle_probs = self._calculate_node_probabilities(self.middle_nodes)
        exit_probs = self._calculate_node_probabilities(self.exit_nodes)
        
        # Start with guard probability
        prob = guard_probs.get(guard_id, 0)
        
        # Multiply by each middle node probability
        for mid in middle_ids:
            prob *= middle_probs.get(mid, 0)
        
        # Multiply by exit probability
        prob *= exit_probs.get(exit_id, 0)
        
        return prob

    def calculate_correlation_attack_probability(self) -> Dict[str, float]:
        """
        Calculate the overall probability that a randomly selected circuit
        will be vulnerable to end-to-end correlation attacks.
        
        A circuit is vulnerable if BOTH the guard and exit nodes are compromised,
        allowing an adversary to correlate entry and exit traffic.
        """
        guard_probs = self._calculate_node_probabilities(self.guard_nodes)
        middle_probs = self._calculate_node_probabilities(self.middle_nodes)
        exit_probs = self._calculate_node_probabilities(self.exit_nodes)

        total_attack_prob = 0.0
        total_full_compromise_prob = 0.0
        compromised_count = 0
        fully_compromised_count = 0
        total_circuits = 0

        # Generate all possible middle node orderings
        middle_combinations = list(permutations(self.middle_nodes, self.num_middle_nodes))

        # Iterate through all possible circuits
        for guard in self.guard_nodes:
            for middle_combo in middle_combinations:
                for exit_node in self.exit_nodes:
                    # Ensure all nodes in circuit are unique
                    circuit_ids = {guard.id, exit_node.id}
                    circuit_ids.update(m.id for m in middle_combo)

                    if len(circuit_ids) < 2 + self.num_middle_nodes:
                        continue  # Skip circuits with duplicate nodes

                    total_circuits += 1

                    # Calculate probability of this specific circuit being chosen
                    circuit_prob = (guard_probs.get(guard.id, 0) * 
                                   exit_probs.get(exit_node.id, 0))
                    for middle_node in middle_combo:
                        circuit_prob *= middle_probs.get(middle_node.id, 0)

                    # Check for correlation attack vulnerability (guard AND exit)
                    if guard.compromised and exit_node.compromised:
                        total_attack_prob += circuit_prob
                        compromised_count += 1

                    # Check for full compromise (ALL nodes)
                    if (guard.compromised and exit_node.compromised and 
                        all(m.compromised for m in middle_combo)):
                        total_full_compromise_prob += circuit_prob
                        fully_compromised_count += 1

        # Calculate compromise rates per node type
        guard_compromise_rate = (
            sum(1 for g in self.guard_nodes if g.compromised) / len(self.guard_nodes)
            if self.guard_nodes else 0
        )
        exit_compromise_rate = (
            sum(1 for e in self.exit_nodes if e.compromised) / len(self.exit_nodes)
            if self.exit_nodes else 0
        )
        middle_compromise_rate = (
            sum(1 for m in self.middle_nodes if m.compromised) / len(self.middle_nodes)
            if self.middle_nodes else 0
        )

        return {
            'total_attack_probability': total_attack_prob,
            'total_full_compromise_probability': total_full_compromise_prob,
            'guard_compromise_rate': guard_compromise_rate,
            'middle_compromise_rate': middle_compromise_rate,
            'exit_compromise_rate': exit_compromise_rate,
            'compromised_circuits': compromised_count,
            'fully_compromised_circuits': fully_compromised_count,
            'total_circuits': total_circuits,
            'vulnerable_percentage': (
                (compromised_count / total_circuits * 100) if total_circuits > 0 else 0
            ),
            'fully_compromised_percentage': (
                (fully_compromised_count / total_circuits * 100) if total_circuits > 0 else 0
            )
        }

    def get_vulnerable_circuits(self, top_n: int = 10, 
                               fully_compromised_only: bool = False) -> List[Dict]:
        """
        Identify the most probable vulnerable circuits.
        """
        guard_probs = self._calculate_node_probabilities(self.guard_nodes)
        middle_probs = self._calculate_node_probabilities(self.middle_nodes)
        exit_probs = self._calculate_node_probabilities(self.exit_nodes)

        vulnerable_circuits = []
        middle_combinations = list(permutations(self.middle_nodes, self.num_middle_nodes))

        for guard in self.guard_nodes:
            for middle_combo in middle_combinations:
                for exit_node in self.exit_nodes:
                    # Ensure unique nodes
                    circuit_ids = {guard.id, exit_node.id}
                    circuit_ids.update(m.id for m in middle_combo)
                    if len(circuit_ids) < 2 + self.num_middle_nodes:
                        continue
                    
                    # Check vulnerability types
                    is_correlation_vulnerable = guard.compromised and exit_node.compromised
                    is_fully_compromised = (is_correlation_vulnerable and 
                                          all(m.compromised for m in middle_combo))
                    
                    # Filter based on requested type
                    if fully_compromised_only:
                        if not is_fully_compromised:
                            continue
                    else:
                        if not is_correlation_vulnerable:
                            continue
                    
                    # Calculate circuit probability
                    circuit_prob = (guard_probs.get(guard.id, 0) * 
                                   exit_probs.get(exit_node.id, 0))
                    for m in middle_combo:
                        circuit_prob *= middle_probs.get(m.id, 0)
                    
                    vulnerable_circuits.append({
                        'guard_id': guard.id,
                        'middle_ids': [m.id for m in middle_combo],
                        'exit_id': exit_node.id,
                        'probability': circuit_prob,
                        'fully_compromised': is_fully_compromised
                    })

        # Sort by probability (most likely first) and return top N
        vulnerable_circuits.sort(key=lambda x: x['probability'], reverse=True)
        return vulnerable_circuits[:top_n]

    def simulate_attack_scenarios(self, compromise_rates: List[float]) -> Dict:
        """
        Simulate different adversary capabilities by varying node compromise rates.
        Temporarily compromises nodes to evaluate attack effectiveness.
        """
        results = {}
        
        # Save original compromise states
        original_states = {
            node.id: node.compromised 
            for node in (self.guard_nodes + self.exit_nodes)
        }

        for rate in compromise_rates:
            # Sort by bandwidth to compromise highest-capacity nodes first
            all_guards = sorted(self.guard_nodes, key=lambda n: n.band_width, reverse=True)
            all_exits = sorted(self.exit_nodes, key=lambda n: n.band_width, reverse=True)

            num_compromised_guards = int(len(all_guards) * rate)
            num_compromised_exits = int(len(all_exits) * rate)

            # Reset all nodes
            for node in (self.guard_nodes + self.exit_nodes):
                node.compromised = False

            # Compromise top nodes according to rate
            for i in range(num_compromised_guards):
                all_guards[i].compromised = True
            for i in range(num_compromised_exits):
                all_exits[i].compromised = True

            # Calculate attack probabilities for this scenario
            results[rate] = self.calculate_correlation_attack_probability()

        # Restore original states
        for node in (self.guard_nodes + self.exit_nodes):
            node.compromised = original_states.get(node.id, False)

        return results

    def display_attack_results(self, results: dict):
        """
        Display attack probability results in a clean, readable format.
        Handles both single-run results and multi-scenario simulation results.
        """
        def format_single(result: dict):
            """Format a single result as a readable report"""
            lines = [
                "📊  Correlation Attack Analysis",
                "───────────────────────────────",
                f"Total Circuits:                    {result['total_circuits']:,}",
                "",
                "Correlation Attack (Guard + Exit compromised):",
                f"  Vulnerable Circuits:             {result['compromised_circuits']:,}",
                f"  Vulnerable Percentage:           {result['vulnerable_percentage']:.2f}%",
                f"  Attack Probability:              {result['total_attack_probability']:.2%}",
                "",
                "Full Compromise (All nodes compromised):",
                f"  Fully Compromised Circuits:      {result['fully_compromised_circuits']:,}",
                f"  Fully Compromised Percentage:    {result['fully_compromised_percentage']:.2f}%",
                f"  Full Compromise Probability:     {result['total_full_compromise_probability']:.2%}",
                "",
                "Node Compromise Rates:",
                f"  Guard:                           {result['guard_compromise_rate']:.2%}",
                f"  Middle:                          {result['middle_compromise_rate']:.2%}",
                f"  Exit:                            {result['exit_compromise_rate']:.2%}",
            ]
            return "\n".join(lines)

        # Check if this is a multi-scenario simulation result
        if all(isinstance(v, dict) for v in results.values()):
            # Display comparison table across compromise rates
            print("🧪  Simulation Results Across Compromise Rates")
            print("──────────────────────────────────────────────")
            print(f"{'Rate':>6} | {'Vuln %':>9} | {'Full %':>9} | "
                  f"{'Corr. Prob':>12} | {'Full Prob':>12}")
            print("-" * 62)
            for rate, res in results.items():
                print(f"{rate:>5.2f} | {res['vulnerable_percentage']:>8.2f}% | "
                      f"{res['fully_compromised_percentage']:>8.2f}% | "
                      f"{res['total_attack_probability']:>11.6f} | "
                      f"{res['total_full_compromise_probability']:>11.6f}")
            print("-" * 62)
        else:
            # Display single result report
            print(format_single(results))
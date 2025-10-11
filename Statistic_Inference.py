from dataclasses import dataclass
from typing import List, Dict
from itertools import permutations

@dataclass
class Node:
    id: str
    band_width: float
    uptime: float
    is_guard: bool = False
    is_exit: bool = False
    is_middle: bool = False
    compromised: bool = False  # <- using this consistently

class Probabilities:
    def __init__(self, bandwidth_weight: float = 0.95, uptime_weight: float = 0.05, num_middle_nodes: int = 1):
        self.bandwidth_weight = bandwidth_weight
        self.uptime_weight = uptime_weight
        self.num_middle_nodes = num_middle_nodes
        self.guard_nodes: List[Node] = []
        self.middle_nodes: List[Node] = []
        self.exit_nodes: List[Node] = []

    def _calculate_node_probabilities(self, nodes: List[Node]) -> Dict[str, float]:
        if not nodes:
            return {}
        node_scores = {
            node.id: (node.band_width * self.bandwidth_weight + node.uptime * self.uptime_weight)
            for node in nodes
        }
        total_score = sum(node_scores.values())
        if total_score == 0:
            prob = 1.0 / len(nodes)
            return {node.id: prob for node in nodes}
        return {nid: score / total_score for nid, score in node_scores.items()}

    def set_nodes(self, guard_nodes: List[Node], middle_nodes: List[Node], exit_nodes: List[Node]):
        self.guard_nodes = guard_nodes
        self.middle_nodes = middle_nodes
        self.exit_nodes = exit_nodes

    def calculate_circuit_probability(self, guard_id: str, middle_ids: List[str], exit_id: str) -> float:
        guard_probs = self._calculate_node_probabilities(self.guard_nodes)
        middle_probs = self._calculate_node_probabilities(self.middle_nodes)
        exit_probs = self._calculate_node_probabilities(self.exit_nodes)
        prob = guard_probs.get(guard_id, 0)
        for mid in middle_ids:
            prob *= middle_probs.get(mid, 0)
        prob *= exit_probs.get(exit_id, 0)
        return prob

    def calculate_correlation_attack_probability(self) -> Dict[str, float]:
        guard_probs = self._calculate_node_probabilities(self.guard_nodes)
        middle_probs = self._calculate_node_probabilities(self.middle_nodes)
        exit_probs = self._calculate_node_probabilities(self.exit_nodes)

        total_attack_prob = 0.0
        total_full_compromise_prob = 0.0
        compromised_count = 0
        fully_compromised_count = 0
        total_circuits = 0

        middle_combinations = list(permutations(self.middle_nodes, self.num_middle_nodes))

        for guard in self.guard_nodes:
            for middle_combo in middle_combinations:
                for exit_node in self.exit_nodes:
                    circuit_ids = {guard.id, exit_node.id}
                    circuit_ids.update(m.id for m in middle_combo)

                    if len(circuit_ids) < 2 + self.num_middle_nodes:
                        continue

                    total_circuits += 1

                    circuit_prob = guard_probs.get(guard.id, 0) * exit_probs.get(exit_node.id, 0)
                    for middle_node in middle_combo:
                        circuit_prob *= middle_probs.get(middle_node.id, 0)

                    # Correlation attack (guard AND exit compromised)
                    if guard.compromised and exit_node.compromised:
                        total_attack_prob += circuit_prob
                        compromised_count += 1

                    # Full compromise (ALL nodes compromised)
                    if guard.compromised and exit_node.compromised and all(m.compromised for m in middle_combo):
                        total_full_compromise_prob += circuit_prob
                        fully_compromised_count += 1

        guard_compromise_rate = (sum(1 for g in self.guard_nodes if g.compromised) / len(self.guard_nodes)) if self.guard_nodes else 0
        exit_compromise_rate = (sum(1 for e in self.exit_nodes if e.compromised) / len(self.exit_nodes)) if self.exit_nodes else 0
        middle_compromise_rate = (sum(1 for m in self.middle_nodes if m.compromised) / len(self.middle_nodes)) if self.middle_nodes else 0

        return {
            'total_attack_probability': total_attack_prob,
            'total_full_compromise_probability': total_full_compromise_prob,
            'guard_compromise_rate': guard_compromise_rate,
            'middle_compromise_rate': middle_compromise_rate,
            'exit_compromise_rate': exit_compromise_rate,
            'compromised_circuits': compromised_count,
            'fully_compromised_circuits': fully_compromised_count,
            'total_circuits': total_circuits,
            'vulnerable_percentage': (compromised_count / total_circuits * 100) if total_circuits > 0 else 0,
            'fully_compromised_percentage': (fully_compromised_count / total_circuits * 100) if total_circuits > 0 else 0
        }

    def get_vulnerable_circuits(self, top_n: int = 10, fully_compromised_only: bool = False):
        guard_probs = self._calculate_node_probabilities(self.guard_nodes)
        middle_probs = self._calculate_node_probabilities(self.middle_nodes)
        exit_probs = self._calculate_node_probabilities(self.exit_nodes)

        vulnerable_circuits = []
        middle_combinations = list(permutations(self.middle_nodes, self.num_middle_nodes))

        for guard in self.guard_nodes:
            for middle_combo in middle_combinations:
                for exit_node in self.exit_nodes:
                    circuit_ids = {guard.id, exit_node.id}
                    circuit_ids.update(m.id for m in middle_combo)
                    if len(circuit_ids) < 2 + self.num_middle_nodes:
                        continue
                    
                    # Check for correlation attack (guard and exit)
                    is_correlation_vulnerable = guard.compromised and exit_node.compromised
                    # Check for full compromise (all nodes)
                    is_fully_compromised = is_correlation_vulnerable and all(m.compromised for m in middle_combo)
                    
                    if fully_compromised_only:
                        if not is_fully_compromised:
                            continue
                    else:
                        if not is_correlation_vulnerable:
                            continue
                    
                    circuit_prob = guard_probs.get(guard.id, 0) * exit_probs.get(exit_node.id, 0)
                    for m in middle_combo:
                        circuit_prob *= middle_probs.get(m.id, 0)
                    vulnerable_circuits.append({
                        'guard_id': guard.id,
                        'middle_ids': [m.id for m in middle_combo],
                        'exit_id': exit_node.id,
                        'probability': circuit_prob,
                        'fully_compromised': is_fully_compromised
                    })

        vulnerable_circuits.sort(key=lambda x: x['probability'], reverse=True)
        return vulnerable_circuits[:top_n]

    def simulate_attack_scenarios(self, compromise_rates: List[float]):
        results = {}
        original_states = {node.id: node.compromised for node in (self.guard_nodes + self.exit_nodes)}

        for rate in compromise_rates:
            all_guards = sorted(self.guard_nodes, key=lambda n: n.band_width, reverse=True)
            all_exits = sorted(self.exit_nodes, key=lambda n: n.band_width, reverse=True)

            num_compromised_guards = int(len(all_guards) * rate)
            num_compromised_exits = int(len(all_exits) * rate)

            for node in (self.guard_nodes + self.exit_nodes):
                node.compromised = False

            for i in range(num_compromised_guards):
                all_guards[i].compromised = True
            for i in range(num_compromised_exits):
                all_exits[i].compromised = True

            results[rate] = self.calculate_correlation_attack_probability()

        for node in (self.guard_nodes + self.exit_nodes):
            node.compromised = original_states.get(node.id, False)

        return results

    def display_attack_results(self, results: dict):
        """
        Display attack probability results in a clean, minimal format.
        Supports both single-run and multi-scenario results.
        """

        def format_single(result: dict):
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

        # Case 1: Results for multiple compromise rates (from simulate_attack_scenarios)
        if all(isinstance(v, dict) for v in results.values()):
            print("🧪  Simulation Results Across Compromise Rates")
            print("──────────────────────────────────────────────")
            print(f"{'Rate':>6} | {'Vuln %':>9} | {'Full %':>9} | {'Corr. Prob':>12} | {'Full Prob':>12}")
            print("-" * 62)
            for rate, res in results.items():
                print(f"{rate:>5.2f} | {res['vulnerable_percentage']:>8.2f}% | {res['fully_compromised_percentage']:>8.2f}% | {res['total_attack_probability']:>11.6f} | {res['total_full_compromise_probability']:>11.6f}")
            print("-" * 62)
        else:
            # Case 2: Single result dictionary
            print(format_single(results))
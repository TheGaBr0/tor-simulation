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
        compromised_count = 0
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

                    if guard.compromised and exit_node.compromised:
                        total_attack_prob += circuit_prob
                        compromised_count += 1

        guard_compromise_rate = (sum(1 for g in self.guard_nodes if g.compromised) / len(self.guard_nodes)) if self.guard_nodes else 0
        exit_compromise_rate = (sum(1 for e in self.exit_nodes if e.compromised) / len(self.exit_nodes)) if self.exit_nodes else 0

        return {
            'total_attack_probability': total_attack_prob,
            'guard_compromise_rate': guard_compromise_rate,
            'exit_compromise_rate': exit_compromise_rate,
            'compromised_circuits': compromised_count,
            'total_circuits': total_circuits,
            'vulnerable_percentage': (compromised_count / total_circuits * 100) if total_circuits > 0 else 0
        }

    def get_vulnerable_circuits(self, top_n: int = 10):
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
                    if guard.compromised and exit_node.compromised:
                        circuit_prob = guard_probs.get(guard.id, 0) * exit_probs.get(exit_node.id, 0)
                        for m in middle_combo:
                            circuit_prob *= middle_probs.get(m.id, 0)
                        vulnerable_circuits.append({
                            'guard_id': guard.id,
                            'middle_ids': [m.id for m in middle_combo],
                            'exit_id': exit_node.id,
                            'probability': circuit_prob
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

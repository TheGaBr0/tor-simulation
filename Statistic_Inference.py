
from typing import List, Tuple
from collections import defaultdict
import itertools
from Node import *

class probCalculator:
    def __init__(self, nodes: List[Node]):
        self.nodes=nodes


    def get_16_subnet(self,ip: str) -> str:
        """Estrae la subnet /16 da un indirizzo IP"""
        return '.'.join(ip.split('.')[:2])
     
    def calculate_diversity_constrained_probability(
            self,
        bandwidth_weight: float = 0.95,
        uptime_weight: float = 0.05,
        top_n: int = 3,
        num_simulations: int = 5000
    ) -> dict:
        """
        Calcola la probabilità considerando anche i vincoli di diversità
        (stesso owner e stessa /16 subnet non possono essere scelti).
        
        Questa è una versione più accurata che considera le dipendenze
        tra la selezione di guard ed exit.
        """
        
        guards = [n for n in self.nodes if n.type == 'guard']
        exits = [n for n in self.nodes if n.type == 'exit']
        
        import random
        
        # Calcola score
        guard_scores = [(g, g.band_width * bandwidth_weight + g.uptime * uptime_weight) 
                        for g in guards]
        exit_scores = [(e, e.band_width * bandwidth_weight + e.uptime * uptime_weight) 
                    for e in exits]
        
        guard_scores.sort(key=lambda x: x[1], reverse=True)
        exit_scores.sort(key=lambda x: x[1], reverse=True)
        
        top_guards = [g for g, _ in guard_scores[:min(top_n, len(guard_scores))]]
        
        # Contatori
        guard_compromised_count = 0
        exit_compromised_count = 0
        both_compromised_count = 0
        at_least_one_count = 0
        
        for _ in range(num_simulations):
            # Seleziona guard
            selected_guard = random.choice(top_guards)
            
            # Filtra exit che non condividono owner o /16 subnet con il guard
            available_exits = [
                e for e in exits 
                if e.owner != selected_guard.owner 
                and self.get_16_subnet(e.ip) != self.get_16_subnet(selected_guard.ip) # type: ignore
            ]
            
            if not available_exits:
                continue  # Skip questa simulazione se non ci sono exit validi
            
            # Calcola score per exit disponibili
            available_exit_scores = [
                (e, e.band_width * bandwidth_weight + e.uptime * uptime_weight) 
                for e in available_exits
            ]
            available_exit_scores.sort(key=lambda x: x[1], reverse=True)
            top_available_exits = [e for e, _ in available_exit_scores[:min(top_n, len(available_exit_scores))]]
            
            # Seleziona exit
            selected_exit = random.choice(top_available_exits)
            
            guard_comp = selected_guard.compromised
            exit_comp = selected_exit.compromised
            
            if guard_comp:
                guard_compromised_count += 1
            if exit_comp:
                exit_compromised_count += 1
            if guard_comp and exit_comp:
                both_compromised_count += 1
            if guard_comp or exit_comp:
                at_least_one_count += 1
        
        return {
            'guard_compromised': guard_compromised_count / num_simulations,
            'exit_compromised': exit_compromised_count / num_simulations,
            'both_compromised': both_compromised_count / num_simulations,
            'at_least_one_compromised': at_least_one_count / num_simulations,
            'simulations_run': num_simulations,
        }


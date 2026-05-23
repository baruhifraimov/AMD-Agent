"""MADAR family-aware budget allocation strategies."""

from typing import Protocol


class FamilyBudgetStrategy(Protocol):
    """Allocate replay slots across malware families."""

    def allocate(self, family_counts: dict[str, int], total_budget: int) -> dict[str, int]:
        """Return a mapping of family name to allocated budget."""
        ...


class RatioBudget(FamilyBudgetStrategy):
    """Proportional to family prevalence (Domain-IL default)."""

    def allocate(self, family_counts: dict[str, int], total_budget: int) -> dict[str, int]:
        if not family_counts or total_budget <= 0:
            return {}

        total_samples = sum(family_counts.values())
        if total_samples == 0:
            return {}

        budgets = {}
        for family, count in family_counts.items():
            # Ratio of this family vs all malware samples
            ratio = count / total_samples
            # Allocate proportional budget
            budgets[family] = int(total_budget * ratio)

        # Handle rounding errors (distribute remainder)
        allocated = sum(budgets.values())
        remainder = total_budget - allocated

        # Distribute remainder to largest families first
        if remainder > 0:
            sorted_families = sorted(
                family_counts.keys(), key=lambda f: family_counts[f], reverse=True
            )
            for i in range(remainder):
                family = sorted_families[i % len(sorted_families)]
                budgets[family] = budgets.get(family, 0) + 1

        return budgets


class UniformBudget(FamilyBudgetStrategy):
    """Equal budget per family (Class-IL / Task-IL default)."""

    def allocate(self, family_counts: dict[str, int], total_budget: int) -> dict[str, int]:
        if not family_counts or total_budget <= 0:
            return {}

        num_families = len(family_counts)
        base_budget = total_budget // num_families
        remainder = total_budget % num_families

        budgets = {family: base_budget for family in family_counts}

        # Distribute remainder to largest families first
        if remainder > 0:
            sorted_families = sorted(
                family_counts.keys(), key=lambda f: family_counts[f], reverse=True
            )
            for i in range(remainder):
                family = sorted_families[i % len(sorted_families)]
                budgets[family] = budgets.get(family, 0) + 1

        return budgets

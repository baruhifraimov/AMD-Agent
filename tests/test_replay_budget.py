import pytest

from src.ml.replay_budget import RatioBudget, UniformBudget

def test_ratio_budget_allocation():
    strategy = RatioBudget()
    counts = {"fam1": 100, "fam2": 50, "fam3": 50}
    budget = 100
    
    alloc = strategy.allocate(counts, budget)
    assert alloc["fam1"] == 50
    assert alloc["fam2"] == 25
    assert alloc["fam3"] == 25
    assert sum(alloc.values()) == budget

def test_uniform_budget_allocation():
    strategy = UniformBudget()
    counts = {"fam1": 100, "fam2": 50, "fam3": 10}
    budget = 100
    
    alloc = strategy.allocate(counts, budget)
    # 100 / 3 = 33, remainder 1
    # fam1 gets 34, fam2 gets 33, fam3 gets 33
    assert alloc["fam1"] == 34
    assert alloc["fam2"] == 33
    assert alloc["fam3"] == 33
    assert sum(alloc.values()) == budget

def test_budget_empty():
    strategy = RatioBudget()
    assert strategy.allocate({}, 100) == {}
    assert strategy.allocate({"fam1": 10}, 0) == {}

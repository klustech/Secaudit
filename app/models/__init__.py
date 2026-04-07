from app.models.repo_analysis import RepoAnalysis, AnalyzeRequest
from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.risk_flag import RiskFlag
from app.models.value_movement import ValueMovementEdge, ValueMovementReport
from app.models.review_property import ReviewProperty, PropertyChecklistReport
from app.models.risk_scenario import RiskScenario, RiskScenarioReport
# Deprecated — kept for backward compatibility
from app.models.fund_flow import FundFlowEdge, FundFlowGraph
from app.models.attack_surface import Invariant, InvariantReport
from app.models.attack_path import AttackPath, AttackSurfaceReport

__all__ = [
    "RepoAnalysis", "AnalyzeRequest", "ContractInfo", "FunctionInfo", "RiskFlag",
    # New models
    "ValueMovementEdge", "ValueMovementReport",
    "ReviewProperty", "PropertyChecklistReport",
    "RiskScenario", "RiskScenarioReport",
    # Deprecated
    "FundFlowEdge", "FundFlowGraph", "Invariant", "InvariantReport",
    "AttackPath", "AttackSurfaceReport",
]

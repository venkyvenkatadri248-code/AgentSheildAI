from enum import Enum
from typing import Set, Dict


class LifecycleState(str, Enum):
    OBSERVED = "OBSERVED"
    SUSPICIOUS = "SUSPICIOUS"
    DETECTED = "DETECTED"
    BLOCKED = "BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    MITIGATION_IN_PROGRESS = "MITIGATION_IN_PROGRESS"
    PREVENTION_VERIFIED = "PREVENTION_VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"


# Valid deterministic state transitions
VALID_TRANSITIONS: Dict[LifecycleState, Set[LifecycleState]] = {
    LifecycleState.OBSERVED: {
        LifecycleState.SUSPICIOUS,
        LifecycleState.DETECTED,
        LifecycleState.BLOCKED,
        LifecycleState.PENDING_APPROVAL,
        LifecycleState.MITIGATION_IN_PROGRESS,
        LifecycleState.TASK_COMPLETED,
        LifecycleState.TASK_FAILED,
    },
    LifecycleState.SUSPICIOUS: {
        LifecycleState.DETECTED,
        LifecycleState.BLOCKED,
        LifecycleState.PENDING_APPROVAL,
        LifecycleState.TASK_COMPLETED,
        LifecycleState.TASK_FAILED,
    },
    LifecycleState.DETECTED: {
        LifecycleState.BLOCKED,
        LifecycleState.PENDING_APPROVAL,
        LifecycleState.MITIGATION_IN_PROGRESS,
    },
    LifecycleState.BLOCKED: {
        LifecycleState.PREVENTION_VERIFIED,
        LifecycleState.VERIFICATION_FAILED,
    },
    LifecycleState.PENDING_APPROVAL: {
        LifecycleState.MITIGATION_IN_PROGRESS,  # On approval
        LifecycleState.BLOCKED,                 # On rejection
    },
    LifecycleState.MITIGATION_IN_PROGRESS: {
        LifecycleState.TASK_COMPLETED,
        LifecycleState.TASK_FAILED,
        LifecycleState.PREVENTION_VERIFIED,
        LifecycleState.VERIFICATION_FAILED,
    },
    # Terminal states
    LifecycleState.PREVENTION_VERIFIED: set(),
    LifecycleState.VERIFICATION_FAILED: set(),
    LifecycleState.TASK_COMPLETED: set(),
    LifecycleState.TASK_FAILED: set(),
}


class InvalidLifecycleTransitionError(Exception):
    def __init__(self, current_state: str, target_state: str):
        super().__init__(f"Invalid lifecycle transition from {current_state} to {target_state}")
        self.current_state = current_state
        self.target_state = target_state


def validate_transition(current: str, target: str) -> bool:
    try:
        curr_enum = LifecycleState(current)
        targ_enum = LifecycleState(target)
    except ValueError:
        return False
    
    allowed = VALID_TRANSITIONS.get(curr_enum, set())
    return targ_enum in allowed

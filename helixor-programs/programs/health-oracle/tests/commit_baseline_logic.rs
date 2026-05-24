// =============================================================================
// programs/health-oracle/tests/commit_baseline_logic.rs
//
// Pure unit tests for the Day-3 state additions. These don't spin up a
// runtime — they exercise the layout constants + helper logic in isolation.
// Full on-chain behaviour is exercised by the Python integration test.
// =============================================================================

use health_oracle::state::AgentRegistration;

#[test]
fn agent_registration_size_constants_are_correct() {
    // v1 + v2 + reserved fields, no padding surprises.
    //   v1:   32 + 32 + 8 + 1 + 1                       = 74
    //   v2:   1 + 32 + 1 + 32 + 8 + 8 + 1               = 83
    //   res:  64                                        = 64
    //   total                                           = 221
    assert_eq!(AgentRegistration::SIZE_WITHOUT_DISCRIMINATOR, 221);
    assert_eq!(AgentRegistration::SPACE, 229);          // + 8 discriminator
    assert_eq!(AgentRegistration::V1_SPACE, 82);        // 8 + 74
}

#[test]
fn current_layout_version_is_two() {
    assert_eq!(AgentRegistration::CURRENT_LAYOUT_VERSION, 2);
}

#[test]
fn v2_is_strictly_larger_than_v1() {
    // The whole reason migrate_registration exists.
    let v2_space = std::hint::black_box(AgentRegistration::SPACE);
    let v1_space = std::hint::black_box(AgentRegistration::V1_SPACE);
    assert!(v2_space > v1_space);
}

pub fn new_context() -> AKEContext {
    return AKEContext{state: AKEState::None};
}

pub struct AKEContext {
    state: AKEState,
}

enum AKEState {
    None,
    AwaitingDHKey,
    AwaitingRevealSignature,
    AwaitingSignature,
}

impl AKEContext {}
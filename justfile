# Prometheus laboratory package. This is not Sanctum product source of truth. This is not a Cyera product.

demo:
    bash scripts/demo.sh
    bash scripts/demo_birth.sh
    bash scripts/demo_depth.sh
    bash scripts/demo_spawn_child.sh
    bash scripts/demo_internal_versus_public.sh
    bash scripts/demo_host.sh
    bash scripts/demo_parent_kill.sh
    bash scripts/demo_tool_loop.sh
    bash scripts/demo_on_behalf.sh
    bash scripts/demo_spawn_authority.sh
    bash scripts/demo_receipt.sh
    bash scripts/demo_log_chain.sh
    bash scripts/demo_accept_issuer.sh
    bash scripts/demo_issuer_rotate.sh
    bash scripts/demo_log_proof.sh
    bash scripts/demo_sign_root.sh
    bash scripts/demo_first_binder.sh
    bash scripts/demo_issuer_seal.sh
    bash scripts/demo_act_bundle.sh
    bash scripts/demo_present.sh
    bash scripts/demo_limit_freeze.sh
    bash scripts/demo_expiry_freeze.sh
    bash scripts/demo_intent_freeze.sh
    bash scripts/demo_threshold.sh
    bash scripts/demo_walkthrough.sh

test:
    cargo test

build:
    cargo build

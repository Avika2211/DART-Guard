# Related work and evidence positioning

This paper's literature review has been expanded in the accompanying Overleaf project, including a comparison table and carefully scoped non-novelty statements.

## Relevant prior-work families
- **Numerical fault injection:** Mahmoud et al., "PyTorchFI: A Runtime Perturbation Tool for DNNs", IEEE/IFIP DSN-W 2020, pp. 25–31, https://github.com/pytorchfi/pytorchfi
- **Simplex/runtime assurance:** Seto, Krogh, Sha and Chutinan, "The Simplex Architecture for Safe Online Control System Upgrades", ACC 1998
- **Action shielding:** Alshiekh et al., "Safe Reinforcement Learning via Shielding", AAAI 2018, https://arxiv.org/abs/1708.08611
- **Dependability/taxonomy:** Avizienis, Laprie, Randell, Landwehr, "Basic Concepts and Taxonomy of Dependable and Secure Computing", IEEE TDSC 2004
- **Programmable LLM guardrails:** NVIDIA NeMo Guardrails, https://github.com/NVIDIA-NeMo/Guardrails
- **Agent benchmark:** Sierra tau-bench and maintained tau3 successor, https://github.com/sierra-research/tau2-bench
- **Sequential environments:** Gymnasium and MiniGrid, Farama Foundation.

## Positioning
DART-Guard does **not** invent FP32 bit flips, redundant execution, Simplex, shielding, authorization or replay protection. The current contribution is a controlled characterization of fault-induced neural decision transitions, a runtime research-layer implementation and bounded external-benchmark measurements. General superiority over runtime assurance/verifier-only or production certification remains unestablished.

Before paper submission, publisher metadata and the post-2025 literature must be independently checked via scholarly search; the connected GitHub tool can verify repositories but cannot certify an exhaustive literature audit.

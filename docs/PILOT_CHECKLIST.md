# Customer pilot checklist

For the team running a pilot, and for the customer's engineers. Broad compatibility must not be claimed until pilots have tested it.

## Before starting

- [ ] Customer's security team reviewed [DATA_FLOW.md](DATA_FLOW.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
- [ ] Decision on local-only or hosted. Hosted needs the [production requirements](PRODUCTION.md) first, or a dedicated isolated instance with agreed risk.
- [ ] Named contacts on both sides, and an agreed way to report findings about our tool.
- [ ] Agreement that this is readiness evidence, and not conformity assessment or legal advice.
- [ ] Customer has a labelled list of a representative product's real dependencies, or agrees to build one.

## Integration

- [ ] `cra prepare` added before CMake configure in the real pipeline.
- [ ] Conan JSON captured from the real install or create.
- [ ] `scope.roots` limited to what is needed.
- [ ] Shipped artifacts and the final image selected explicitly.
- [ ] Vendored and vendor SDK components recorded, and reviewed by someone who knows the product.
- [ ] First bundle inspected by the customer before any upload.
- [ ] No secrets found in a manual search of the bundle.
- [ ] Credentials separated from jobs running untrusted code.

## What to measure

| Question | Method |
| --- | --- |
| Inventory completeness | Compare with the customer's labelled list |
| False components | Same comparison |
| Shipped accuracy | Sample `yes`, `no` and `unknown` against the real image or device |
| Unidentified share | Count of `unknown` shipped, unresolved observations, `not_matchable` |
| False matches | Customer engineers label a sample of findings. `measure.compare_findings` scores it |
| Missed vulnerabilities | Check known past advisories for the product's dependencies |
| Build time cost | CI duration with and without |
| Gate reliability | Rate of `incomplete` and operational failures, with causes |
| Usefulness | Time from finding to decision; engineers' feedback on explanations |

## Decisions to record

- [ ] Policy agreed for build and release modes, with an owner and a version.
- [ ] Trusted VEX authors named, and repository review enforced on those files.
- [ ] Response to `incomplete`: block, or a visible exception process.
- [ ] Retention period agreed.
- [ ] Upgrade process: who reviews, how pins change, how to roll back.

## Exit criteria

- [ ] Agreed completeness and false-match thresholds met on real products.
- [ ] No unexplained `passed` outcomes, checked by sampling.
- [ ] Every tool failure seen is understood, with a cause recorded.
- [ ] Limitations specific to this customer written down and accepted.
- [ ] Compatibility claims limited to the toolchains actually tested.

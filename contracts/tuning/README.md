# Offline threshold comparison contracts

`threshold_corpus_v1.schema.json` describes privacy-free aggregate fixtures for
the four frozen v0.1 deterministic rules. Raw and deduplicated counts are
separate so duplicate delivery cannot inflate evidence. Evidence health is
explicit, and incomplete, untrusted, or unverified cases must remain
non-enforcement-supporting for every profile.

`threshold_report_v1.schema.json` records the author, evaluation time, exact
raw/canonical dataset digests, active detector version/digest, prior threshold
values, three offline profiles, per-case decisions, confusion matrices, and a
no-activation recommendation. The comparator has no runtime configuration
write path. A candidate cannot become eligible if it introduces an attack miss,
a false-positive regression, or an evidence-guard regression relative to the
frozen baseline.

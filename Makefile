.PHONY: check check-backend check-contracts check-database check-docs check-export check-frontend check-gateway-performance check-images check-integration check-nft-namespace check-observability check-recovery check-security check-supply-chain check-threshold-tuning

check: check-backend check-contracts check-docs check-frontend check-security check-supply-chain check-threshold-tuning

check-backend:
	./scripts/check-backend.sh

check-contracts:
	node scripts/generate-contract-vectors.mjs --check

check-database:
	./db/test/verify.sh

check-docs:
	node scripts/validate-docs.mjs
	npx --yes markdownlint-cli --disable MD013 MD024 -- README.md AGENTS.md docs/*.md
	git diff --check

check-export:
	./scripts/check-export.sh

check-frontend:
	npm --prefix web ci
	npm --prefix web run verify

check-gateway-performance:
	./scripts/check-gateway-performance.sh

check-images:
	./scripts/check-images.sh

check-nft-namespace:
	./scripts/preflight-nft-namespace.sh

check-observability:
	./deployments/observability/verify.sh

check-recovery:
	./scripts/check-backup-restore.sh

check-integration: check-database check-nft-namespace check-images check-observability check-recovery check-export

check-security:
	./scripts/check-security.sh

check-supply-chain:
	./scripts/check-supply-chain.sh

check-threshold-tuning:
	./scripts/check-threshold-tuning.sh

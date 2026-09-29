.PHONY: salt up down check check-no-up scans observe switch clean engine-test engine-logs \
        attack attack-nikto attack-fast attack-nmap attack-human attack-start attack-stop \
        extract-test extract-features trap-secret

# Generate the pseudonymisation salt (once per deployment). Never committed.
salt:
	@mkdir -p secrets
	@test -f secrets/source_salt.env && echo "salt: secrets/source_salt.env already exists (not overwriting)" || { \
		printf 'CHAMELEON_SOURCE_SALT=%s\n' "$$(python3 -c 'import secrets;print(secrets.token_hex(32))')" > secrets/source_salt.env; \
		chmod 600 secrets/source_salt.env; \
		echo "salt: wrote secrets/source_salt.env"; }

up:
	docker compose up -d

down:
	docker compose down

# Full build gate: bring the stack up, then run both quality gates.
check:
	./tools/check.sh

# Run the gates against an already-running stack (no docker compose).
check-no-up:
	./tools/check.sh --no-up

# Run just the two scanners (stack must already be up).
scans:
	./tools/give_away_scan.py
	./tools/coherence_check.py

# Capture design reference from a live Moodle (measure; you build).
observe:
	./tools/observe.sh https://sandbox405.moodledemo.net --output evidence/observed/sandbox405

clean:
	docker compose down --remove-orphans --volumes

# Rotate the served persona at runtime (default moodle): make switch P=finance
switch:
	./tools/switch_persona.sh $(P)

# Generate a deployment-specific honeytrap cookie secret AND recompute the
# MACs nginx issues with it. Both together, never one without the other:
# rotating the secret alone makes every untouched client look like it
# tampered with the cookie. Verify at any time with:
#   python3 tools/rotate_trap_secret.py --check
trap-secret:
	./tools/rotate_trap_secret.py

# Phase 4 engine self-test (host Python only, no containers).
engine-test:
	python3 engine/self_test.py

# Tail the engine's output (must be running).
engine-logs:
	docker compose logs -f engine

# Build the attacker image.
attack:
	docker compose --profile attack build attacker

# Start a persistent attack container (stay in background, exec in).
attack-start:
	docker compose --profile attack up -d attacker

# Stop and remove the attack container.
attack-stop:
	docker compose --profile attack rm -sf attacker

# Run a nikto scan against the proxy via the attacker container.
attack-nikto:
	docker compose --profile attack run --rm attacker ./nikto-blitz.sh

# Run fast scanner-like probes (60+ rapid requests to /wp-admin etc).
attack-fast:
	docker compose --profile attack run --rm attacker ./fast-probes.sh

# Run an nmap service scan.
attack-nmap:
	docker compose --profile attack run --rm attacker ./nmap-scan.sh

# Simulate normal human-like browsing (no detection expected).
attack-human:
	docker compose --profile attack run --rm attacker ./human-browse.sh

# Phase 6 feature-extractor self-test (host Python only, no containers).
extract-test:
	python3 analysis/self_test.py

# Extract one CSV row per session from a Caddy access log:
#   make extract-features LOG=/path/to/access.json OUT=features.csv
extract-features:
	python3 analysis/extract_features.py $(LOG) --out $(OUT)

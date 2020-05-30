#!/usr/bin/env bats
TEST_BREW_PREFIX="$(brew --prefix)"
load "${TEST_BREW_PREFIX}/lib/bats-support/load.bash"
load "${TEST_BREW_PREFIX}/lib/bats-assert/load.bash"


flunk() {
  { if [ "$#" -eq 0 ]; then cat -
    else echo "$@"
    fi
  } | sed "s:${BATS_TMPDIR}:\${BATS_TMPDIR}:g" >&2
  return 1
}

refute_equal() {
  if [ "$1" = "$2" ]; then
    flunk "unexpectedly equal: $1"
  fi
}

assert_not_equal() {
  refute_equal "$@"
}

assert_starts_with() {
  if [ "$1" = "${1#${2}}" ]; then
    { echo "expected: $1"
      echo "to start with: $2"
    } | flunk
  fi
}

assert_output_contains() {
  local expected
  if [ $# -eq 0 ]; then expected="$(cat -)"
  else expected="$1"
  fi
  assert_contains "$output" "$expected"
}

refute_contains() {
  local haystack="$1"
  local needle="$2"
  ! assert_contains "$haystack" "$needle" || {
    { echo "expected:       $haystack"
      echo "not to contain: $needle"
    } | flunk
  }
}

refute_output_contains() {
  local expected
  if [ $# -eq 0 ]; then expected="$(cat -)"
  else expected="$1"
  fi
  refute_contains "$output" "$expected"
 


@test "test well-formulated, level 2, quality practices image" {
  run bash -c "conftest test -i Dockerfile Dockerfile.level2 --data .opacisrc.level2 -p ../policy"
  assert_output_contains "11 tests, 11 passed, 0 warnings, 0 failures"
  refute_output_contains "FAIL"
  refute_output_contains "WARN"
}

@test "test strong, level 1 image" {
  run bash -c "conftest test Dockerfile --data .opacisrc -p ../policy"
  assert_output_contains "11 tests, 11 passed, 0 warnings, 0 failures"
  refute_output_contains "FAIL"
  refute_output_contains "WARN"
}

@test "test strong, level 1 image with level 2 flag" {
  run bash -c "conftest test Dockerfile --data .opacisrc.l2flag -p ../policy"
  assert_output_contains "4.8 Ensure setuid and setgid permissions are removed in the images (Not Scored) level 2"
  assert_output_contains "4.5 Ensure Content trust for Docker is Enabled (Scored) level 2"
  assert_output_contains "FAIL"
  assert_output_contains "WARN"
  refute_output_contains "PASS"
}

@test "test poor security practices image" {
  run bash -c "conftest test -i Dockerfile Dockerfile.poor --data .opacisrc.poor -p ../policy"
  assert_output_contains "4.3 Ensure unnecessary packages are not installed in the container (Not Scored) level 1"
  assert_output_contains "4.4 Ensure images are scanned and rebuilt to include security patches (Not Scored) level 1"
  assert_output_contains "4.10 Ensure secrets are not stored in Dockerfiles (Not Scored) level 1"
  assert_output_contains "4.11 Ensure verified packages are only Installed (Not Scored) level 2"
  assert_output_contains "4.8 Ensure setuid and setgid permissions are removed in the images (Not Scored) level 2"
  assert_output_contains "4.1 Ensure a user for the container has been created (Scored) level 1"
  assert_output_contains "4.2 Ensure that containers use trusted base images (Not Scored) level 1"
  assert_output_contains "4.5 Ensure Content trust for Docker is Enabled (Scored) level 2"
  assert_output_contains "4.6 Ensure HEALTHCHECK instructions have been added to the container image (Scored) level 1"
  assert_output_contains "4.7 Ensure update/upgrade instructions are not used in the Dockerfile (Not Scored) level 1"
  assert_output_contains "4.9 Ensure COPY is used instead of ADD in Dockerfile (Not Scored) level 1"
  assert_output_contains "11 tests, 0 passed, 5 warnings, 6 failures"
  refute_output_contains "PASS"
}

@test "test strong, level 1 image with --trace" {
  run bash -c "conftest test Dockerfile --data .opacisrc -p ../policy --trace | egrep 'Note|PASS|WARN|FAIL'"
  assert_output_contains "4.3 Distroless base or routine evaluation of necessary packages performed (set in .opacisrc)"
  assert_output_contains "4.4 Images are immutable and continuously scanned for cve (set in .opacisrc)"
  assert_output_contains "4.5 Level 1 benchmark - DOCKER_CONTENT_TRUST not required (set in .opacisrc)"
  assert_output_contains "4.6 HEALTHCHECK not required, Kubernetes scheduler used for readiness and liveness rather than Docker healthcheck capability (set in .opacisrc)"
  assert_output_contains "4.6 HEALTHCHECK is defined"
  assert_output_contains "4.8 Level 1 benchmark - setuid/setgid file permission validation not required (set in .opacisrc)"
  assert_output_contains "4.10 Commit hooks and routine repository scannng prevent secrets in Dockerfile (set in .opacisrc)"
  assert_output_contains "4.11 Level 1 benchmark - package verfication not required (set in .opacisrc)"
  assert_output_contains "4.11 Packages installed from verified sources (set in .opacisrc)"
  assert_output_contains "PASS"
  refute_output_contains "FAIL"
  refute_output_contains "WARN"
}

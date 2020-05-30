#!/usr/bin/env bash

permissions=$(docker run --rm $1 find / -perm +6000 -type f -exec ls -ld {} \; 2> /dev/null)

cat <<EOF > .opacisrc
cispolicyconfig:
  level_2_benchmark: false
  run_as_user_required: true
  approved_base_image_not_required: true
  approved_base_images:
    - alpine
  images_not_treated_as_immutable: true
  only_necessary_packages_allowed: false
  healthcheck_required: true
  dockerfile_scanned_for_secrets: false
  packages_verified: false
setuid:
  setuid_or_setgid_values_allow_escalation: "${permissions:-false}"
  docker_content_trust: ${DOCKER_CONTENT_TRUST:-false}
EOF

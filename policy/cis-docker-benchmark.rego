# conftest policy to test docker image for CIS Docker Benchmark compliance
package main

import data.cispolicyconfig
import data.setuid
blacklist = [" update "," upgrade "]


deny[msg] {
  not user_defined
  msg = "4.1 Ensure a user for the container has been created (Scored) level 1"
}

user_defined {
  input[i].Cmd == "user"
}

user_defined {
  cispolicyconfig.run_as_user_required == false
  trace("4.1 USER not required (set in .opacisrc)")
}

deny[msg] {
  not approved_base_image_used
  msg = "4.2 Ensure that containers use trusted base images (Not Scored) level 1"
}

approved_base_image_used {
  cispolicyconfig.approved_base_image_not_required == false
  input[i].Cmd == "from"
  from_image := input[i].Value
  contains(from_image[i], cispolicyconfig.approved_base_images[_])
}

approved_base_image_used {
  cispolicyconfig.approved_base_image_not_required == true
  trace("4.2 Use of specific approved base images not required (set in .opacisrc)")
}

warn[msg] {
  not only_necessary_packages_installed
  msg = "4.3 Ensure unnecessary packages are not installed in the container (Not Scored) level 1"
}

only_necessary_packages_installed {
  cispolicyconfig.only_necessary_packages_allowed == true
  trace("4.3 Distroless base or routine evaluation of necessary packages performed (set in .opacisrc)")
}

warn[msg] {
  not images_scanned_and_rebuilt_not_patched
  msg = "4.4 Ensure images are scanned and rebuilt to include security patches (Not Scored) level 1"
}

images_scanned_and_rebuilt_not_patched {
  cispolicyconfig.images_not_treated_as_immutable == false
  trace("4.4 Images are immutable and continuously scanned for cve (set in .opacisrc)")
}

deny[msg] {
  not trust_defined
  msg = "4.5 Ensure Content trust for Docker is Enabled (Scored) level 2"
}

trust_defined {
  setuid.docker_content_trust == 1
  trace("4.5 DOCKER_CONTENT_TRUST is defined")
} 

trust_defined {
  cispolicyconfig.level_2_benchmark == false
  trace("4.5 Level 1 benchmark - DOCKER_CONTENT_TRUST not required (set in .opacisrc)")
}

deny[msg] {
  not healthcheck_defined
  msg = "4.6 Ensure HEALTHCHECK instructions have been added to the container image (Scored) level 1"
}

healthcheck_defined {
  input[i].Cmd == "healthcheck"
  trace("4.6 HEALTHCHECK is defined")
}

healthcheck_defined {
  cispolicyconfig.healthcheck_required == false
  trace("4.6 HEALTHCHECK not required, Kubernetes scheduler used for readiness and liveness rather than Docker healthcheck capability (set in .opacisrc)")
}

deny[msg] {
  package_update_or_upgrade_instructions
  msg = "4.7 Ensure update/upgrade instructions are not used in the Dockerfile (Not Scored) level 1"
}

package_update_or_upgrade_instructions {
  input[i].Cmd == "run"
  val := concat(" ", input[i].Value)
  contains(val, blacklist[_])
}

warn[msg] {
  not setuid_or_setgid_permissions_reduced
  msg = "4.8 Ensure setuid and setgid permissions are removed in the images (Not Scored) level 2"
  trace(sprintf("setuid/setgid %s",[setuid.setuid_or_setgid_values_allow_escalation]))
}

setuid_or_setgid_permissions_reduced {
  setuid.setuid_or_setgid_values_allow_escalation == false
}

setuid_or_setgid_permissions_reduced {
  cispolicyconfig.level_2_benchmark == false
  trace("4.8 Level 1 benchmark - setuid/setgid file permission validation not required (set in .opacisrc)")
}

deny[msg] {
  input[i].Cmd == "add"
  msg = "4.9 Ensure COPY is used instead of ADD in Dockerfile (Not Scored) level 1"
}

warn[msg] {
  not secrets_not_permitted_in_dockerfile
  msg = "4.10 Ensure secrets are not stored in Dockerfiles (Not Scored) level 1"
}

secrets_not_permitted_in_dockerfile {
  cispolicyconfig.dockerfile_scanned_for_secrets == true
  trace("4.10 Commit hooks and routine repository scannng prevent secrets in Dockerfile (set in .opacisrc)")
}

warn[msg] {
  not only_verified_packages_installed
  msg = "4.11 Ensure verified packages are only Installed (Not Scored) level 2"
}

only_verified_packages_installed {
  cispolicyconfig.packages_verified == true
  trace("4.11 Packages installed from verified sources (set in .opacisrc)")
}

only_verified_packages_installed {
  cispolicyconfig.level_2_benchmark == false
  trace("4.11 Level 1 benchmark - package verfication not required (set in .opacisrc)")
}

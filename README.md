# opa-dockerfile-benchmarks
Use[rego policy](https://www.openpolicyagent.org/docs/latest/policy-language/) with the [Open Policy Agent](https://www.openpolicyagent.org) to apply section four of the CIS Docker Benchmarks.  

This example uses the opa tool, [conftest](https://github.com/open-policy-agent/conftest) to apply the cis-docker-benchmark policy against a local Dockerfile.  

Security policy is as much about demonstrating compliance through policy and demonstrated correlation with practice as it is about specific technology system configurations. Making use of policy-based test frameworks enables policy decisions and related practices to be referenced and document in those situations where there is no obvious 'test' within the current context.

In the case of CIS Benchmarks and the Dockerfile and resulting image tests, how would you automate testing whether or not any unnecessary packages had been installed in the image?  

Using distroless (scratch), or well known tiny images such as Alpine can significantly demonstrate application of this practice since no packages will exist on the image that did not at least extend from an intentional decision.   

The cis-docker-benchmark.rego policy requires a `.opacisrc` configuration file is present that provides additional policy Data in order to report on policy compliance or violation.  

Use `create_rc.sh` from this repo to generate a starting version of this configuration file. For a level 2 CIS Docker banchmark scan of the image, include the name:tag of the image as a parameter to the scripts. Below is an example of the confinguration file for an image that included sudo as part of provided a unqieu user for the image to run as.

```yaml
cispolicyconfig:
  level_2_benchmark: false                  # set true to perform level 2 evaluation
  run_as_user_required: true                # set false if USER defined in approved based images
  approved_base_image_not_required: true    # set false if approved FROM image is required
  approved_base_images:                     # list the registry organziations or image keywords for `contains` search
    -
  images_not_treated_as_immutable: true     # set false if production container images are immutable from initial dev build
  only_necessary_packages_allowed: false    # set true for distroless images or where all packages are reviewed
  healthcheck_required: true                # set false for images that will run on kubernetes or other non-docker clusters
  dockerfile_scanned_for_secrets: false     # set true if cve scanning mechanism in place
  packages_verified: false                  # set true if all packages verified (such as done by alpine apk manager)
setuid:                                     # these setting automatically configured by create_rc.sh 
  setuid_or_setgid_values_allow_escalation: # set to results of file permission scan of running container
  docker_content_trust:                     # set to contents of $DOCKER_CONTENT_TRUST environment variable 
```

With the Dockerfile, .opacisrc, and policy/file.rego in your pwd, run the following command to perform the policy evaluation:  

```bash
$ conftest test Dockerfile --data .opacisrc
```

The test folder includes several examples. 

As a means of bolstering auditability during audit compliance, perform this test as a rouinte part of the CI `build` step and include the --trace flag for `conftest`. This results in full audit information being part of the log of very build.  

Example output:

```bash
PASS - Dockerfile - data.main.warn
TRAC - Dockerfile - Note "4.3 Distroless base or routine evaluation of necessary packages performed (set in .opacisrc)"
TRAC - Dockerfile - Note "4.4 Images are immutable and continuously scanned for cve (set in .opacisrc)"
TRAC - Dockerfile - Note "4.10 Commit hooks and routine repository scannng prevent secrets in Dockerfile (set in .opacisrc)"
TRAC - Dockerfile - Note "4.11 Level 1 benchmark - package verfication not required (set in .opacisrc)"
TRAC - Dockerfile - Note "4.11 Packages installed from verified sources (set in .opacisrc)"
TRAC - Dockerfile - Note "4.8 Level 1 benchmark - setuid/setgid file permission validation not required (set in .opacisrc)"
PASS - Dockerfile - data.main.deny
TRAC - Dockerfile - Note "4.5 Level 1 benchmark - DOCKER_CONTENT_TRUST not required (set in .opacisrc)"
TRAC - Dockerfile - Note "4.6 HEALTHCHECK is defined"
TRAC - Dockerfile - Note "4.6 HEALTHCHECK not required, Kubernetes scheduler used for readiness and liveness rather than Docker healthcheck capability (set in .opacisrc)"
```

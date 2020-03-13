#!/usr/bin/env bash
set -eEuxo pipefail

case $1 in
"cluster-wide")
    ;;
"single-namespace")
    ;;
*)
    echo "bad argument: " + $1
    exit 1
esac

ARTIFACT_DIR=${ARTIFACT_DIR:-}

function teardown {
    if [[ -n "${ARTIFACT_DIR}" ]]; then
        oc logs -n "${PROJECT}" deploy/openshift-acme > "${ARTIFACT_DIR}"/openshift-acme_deploy.log || true
    fi
}
trap teardown ERR EXIT

TEST_DOMAIN={TEST_DOMAIN:-""}
export TEST_DOMAIN

# Deploy
PROJECT=${PROJECT:-acme-controller}
oc new-project "${PROJECT}" || true


case $1 in
"cluster-wide")
    export FIXED_NAMESPACE=""
    ;;
"single-namespace")
    oc create user developer
    oc create clusterrolebinding developer --clusterrole=basic-user --user=developer
    oc adm policy add-role-to-user admin developer -n "${PROJECT}"
    alias oc='oc --as developer'
    # perms sanity checks
    oc auth can-i create clusterrole && exit 1
    oc auth can-i create deployment -n "${PROJECT}"
    export FIXED_NAMESPACE="${PROJECT}"
    ;;
*)
    exit 1
esac

oc apply -fdeploy/$1/{serviceaccount,issuer-letsencrypt-staging}.yaml

case $1 in
"cluster-wide")
    oc adm policy add-cluster-role-to-user openshift-acme -z openshift-acme
    ;;
"single-namespace")
    oc policy add-role-to-user openshift-acme --role-namespace="${PROJECT}" -z openshift-acme
    ;;
*)
    exit 1
esac

cat deploy/$1/deployment.yaml | \
    sed -e "s~quay.io/tnozicka/openshift-acme:controller~registry.svc.ci.openshift.org/"${OPENSHIFT_BUILD_NAMESPACE}"/pipeline:openshift-acme-controller~" | \
    sed -e 's~quay.io/tnozicka/openshift-acme:exposer~registry.svc.ci.openshift.org/"${OPENSHIFT_BUILD_NAMESPACE}"/pipeline:openshift-acme-exposer~' | \
    grep -v -e 'quay.io' -e 'docker.io' | \
   oc apply -f -


# TODO: use subdomains so the domain differs for every test
export DELETE_ACCOUNT_BETWEEN_STEPS_IN_NAMESPACE=${PROJECT}

tmpFile=$( mktemp )

timeout 10m oc rollout status deploy/openshift-acme

make -j64 test-extended GOFLAGS="-v"

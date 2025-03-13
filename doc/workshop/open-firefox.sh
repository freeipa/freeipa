#!/bin/sh

die() {
    >&2 echo $*
    exit 1
}

detach() {
    nohup "$@" >/dev/null 2>&1 </dev/null &
}

usage() {
    cat <<EOF
usage: $(basename "$0") [-p PROFILE] [-r] [URL]"

Open URL in Firefox with the given profile.

Options:

    -p PROFILE   use the given profile name
    -r           remove the profile

EOF
}


MOZILLA_PROFILES="${HOME}/.mozilla/firefox/profiles.ini"

profile_name="ipa-workshop"
cmd="open"

while getopts ":hp:r" option
do
    case "${option}" in
        h) usage && exit 0 ;;
        p) profile_name="${OPTARG}" ;;
        r) cmd="remove" ;;
        *) die -u "Invalid option: ${OPTARG}" ;;
    esac
done
shift "$((OPTIND - 1))"

[ $# -gt 1 ] && die "Only one URL can be used. (Didn't you forgot '-p'?)"

echo "Using profile ${profile_name}"

WORKSHOP_PROFILE_DIR="${HOME}/.mozilla/firefox/${profile_name}"

if [ "$cmd" == "remove" ]
then
    sed -i "/^\# start - Added by ipalab-config: ${profile_name}$/,/^\# end - Added by ipalab-config: ${profile_name}/d" "${MOZILLA_PROFILES}"
    rm -rf "${WORKSHOP_PROFILE_DIR}"
    exit
fi

if [ ! -d "${WORKSHOP_PROFILE_DIR}" ]
then
    mkdir "${WORKSHOP_PROFILE_DIR}"
    certutil -N -d "${WORKSHOP_PROFILE_DIR}"
    podman cp server:/etc/ipa/ca.crt "${WORKSHOP_PROFILE_DIR}/ca.crt"
    certutil -A -i "${WORKSHOP_PROFILE_DIR}/ca.crt" -d "${WORKSHOP_PROFILE_DIR}" -n "Certificate Authority - IPA dev ${profile_name}" -t "CT,C,"
fi

if ! grep -q "Name=${profile_name}" "${MOZILLA_PROFILES}"
then
    echo "Creating Firefox profile: ${profile_name}"

    next_profile=$(echo $(($(cat "${MOZILLA_PROFILES}" | sed -n 's/\[Profile\([^\]]*\)\]/\1/p' | sort -n | tail -n 1) + 1)))

    cat >> "${MOZILLA_PROFILES}" <<EOF
# start - Added by ipalab-config: ${profile_name}
[Profile${next_profile}]
Name=${profile_name}
IsRelative=1
Path=${profile_name}
# end - Added by FreeIPA Workshop
EOF

fi

[ -z "$@" ] || detach podman unshare --rootless-netns firefox -P "$profile_name" --new-instance --new-window "$@"

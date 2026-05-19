# Practical PKI workshop resources

## Building and deploying the curriculum website

1. Update values in `subst.txt` to match:
    - `BASE_REALM` and `BASE_DOMAIN` match the parent domain of the
      cloud environments.

    - `KEY_LOCATION` is the base URL for where the keys are
      published.  **Don't publish the key for the environment you,
      as presenter, will use.**

    - `FEEDBACK_URL` is the URL of a feedback form.  You should set
      up a feedback form for each workshop you run.

1. Build the site:

    sudo dnf install cabal-install
    cabal run site build

  The built site is now in the `_site` subdirectory.

1. (Optional) Use GitHub pages to publish the site (with a custom
   domain name)
    1. On GitHub, configure the branch name to publish
    1. Update the domain name in the `CNAME` file
    1. Configure `A` records: `185.199.108.153`, `185.199.109.153`,
       `185.199.110.153`, `185.199.111.153`
    1. Commit the `_site` directory to the specified branch.  You
       might find [these Git aliases][aliases] useful, e.g.:
        - `git orphan-branch pki-workshop-devconfcz-2026`
        - `git snapshot _site pki-workshop-devconfcz-2026`
    1. Push the branch.

[aliases]: https://github.com/frasertweedale/dotfiles/blob/d5dbac3ff23fcf65c4e0ec5a54cc0188f1919be4/.gitconfig#L93-L116

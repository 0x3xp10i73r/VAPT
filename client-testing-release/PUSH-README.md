# client-testing-release

Standalone variant of `client-testing/` prepared for its own GitHub repository
(`signal-client-testing`), with all internal paths rewritten for the standalone layout
(scripts at root, documents in `docs/`). Preserved here because the sandbox GitHub token
cannot create new repositories (403 by integration).

Once repo creation is possible:

    cd client-testing-release
    git init -b main && git add -A && git commit -m "Client verification kit — Black Duck Signal 2026.9.0 VAPT findings"
    gh repo create signal-client-testing --private --source . --push

Or, if the repo was created manually on github.com:

    git remote add origin https://github.com/0x3xp10i73r/signal-client-testing.git
    git push -u origin main

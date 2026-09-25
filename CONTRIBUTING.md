# Contributing

Use Node.js 24 or later and work from a clean checkout:

```sh
npm ci
npm test
npm run lint
npm run typecheck
npm run build
```

Run the matching native release contract before changing backend or security behavior:

```sh
npm run verify:windows # Windows 10/11 x64
npm run verify:linux   # Linux
npm run verify:macos   # macOS
```

The platform verification includes the active security contract, doctor, and npm/pnpm lifecycle E2E tests. Do not convert required native tests into mocks or skips. Tests and fixtures must use synthetic secrets only. Report vulnerabilities through the private reporting channel in [SECURITY.md](SECURITY.md).

# vibescan

This is the npm launcher for the local-first `vibescan` security scanner.

The package selects one exact-version `@vibescan/cli-*` optional dependency and
runs the binary shipped inside that package. It has no install script and does
not download a binary. `VIBESCAN_BINARY_PATH` can select an existing local binary
for advanced or air-gapped environments.

After publication, the intended entry point is:

```sh
npx vibescan --version
```

If npm omitted the platform package, reinstall on a clean tree with `npm ci` and
do not reuse `node_modules` across operating systems. The launcher also names the
`cargo install vibescan` and GitHub release installer alternatives.

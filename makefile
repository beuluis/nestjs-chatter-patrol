publish:
	git tag "$$(npm pkg get version | sed 's/\"//g')"
	git push origin "$$(npm pkg get version | sed 's/\"//g')" --no-verify
	npx np --release-draft-only
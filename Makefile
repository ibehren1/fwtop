.PHONY: build clean run dev demo release

build:
	uv sync --dev
	uv run pyinstaller fwtop.spec --clean --noconfirm

clean:
	rm -rf build dist

run: build
	sudo ./dist/fwtop

dev:
	sudo uv run fwtop

demo:
	uv run fwtop --demo

release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=0.1.0)
endif
	git tag v$(VERSION)
	git push origin refs/tags/v$(VERSION)

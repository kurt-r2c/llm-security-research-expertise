.PHONY: help detect status install update uninstall check

SKILLS := ./scripts/skills.sh

help:
	@echo "make detect     list detected agent runtimes and the skills roots they read"
	@echo "make status     show what is installed in each root"
	@echo "make install    install skills/ into every detected root"
	@echo "make update     git pull --ff-only, then reinstall what this repo installed"
	@echo "make uninstall  remove only what this repo installed"
	@echo "make check      shellcheck the installer"
	@echo
	@echo "Variables: MODE=copy|link (default copy), ROOTS=\"dir ...\" (skip detection),"
	@echo "           FORCE=1 (replace or shadow skills not installed by this repo), DRY_RUN=1"

detect:
	@$(SKILLS) detect

status:
	@$(SKILLS) status

install:
	@$(SKILLS) install

update:
	git pull --ff-only
	@$(SKILLS) install

uninstall:
	@$(SKILLS) uninstall

check:
	shellcheck $(SKILLS)

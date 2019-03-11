VERSION := $(shell cat ./VERSION)
NEW_VERSION := $(shell echo $(VERSION)+0.01 | bc)

echo:
	@echo "${NEW_VERSION}"

archive:
	git pull origin $(VERSION)-snapshot:$(VERSION)-snapshot --rebase
	git branch -m $(VERSION)-snapshot $(VERSION)
	git push origin $(VERSION):$(VERSION)
	git push --delete origin $(VERSION)-snapshot
	@echo "$(VERSION) archive done."
	
	@echo "Merge to master."
	git checkout master
	git merge $(VERSION)
	
	@echo "Change to new version: $(NEW_VERSION)."
	git checkout -b $(NEW_VERSION)-snapshot
	echo ${NEW_VERSION} > VERSION
	git add -u
	git commit -m "Initial $(NEW_VERSION)-snapshot"
	
	git push --all
	@echo "Already create new branch: $(NEW_VERSION)"


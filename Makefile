PYTHON ?= python
COVERAGE ?= coverage

.PHONY: test compile coverage demo build ci clean

compile:
	$(PYTHON) -m compileall -q src tests

test:
	$(PYTHON) -m unittest discover -s tests -v

coverage:
	$(COVERAGE) run --source=src/agentguard_graph -m unittest discover -s tests
	$(COVERAGE) report -m --fail-under=85

demo:
	PYTHONPATH=src $(PYTHON) -m agentguard_graph.cli demo

build:
	$(PYTHON) -m build

ci: compile test coverage build demo

clean:
	$(PYTHON) -c "import shutil; [shutil.rmtree(path, ignore_errors=True) for path in ('build', 'dist', 'htmlcov', 'outputs')]"

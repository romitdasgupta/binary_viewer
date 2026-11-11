"""
Learning content for BinaryStudio, as plain data.

The published format, the HTTP routes and the helper functions are documented in
backend/learn_content.py, which is the only module other code should import.
This package holds the content itself:

  concepts_a/b/c.py  the curriculum (modules and concepts)
  glossary.py        glossary terms
  fields.py          per-field explanations for the three formats
  instructions.py    mnemonics and instruction idioms for the disassembly view
  compare.py         the cross-format comparison table
  tours.py           guided tours and their tasks
  resolve.py         turns "where is this in the open file" descriptions into
                     byte ranges and tree nodes, and computes expected answers
  dsl.py             constructors used by the content modules

Standard library only; importable inside Pyodide.
"""

from typing import Any, Dict, List

from . import concepts_a, concepts_b, concepts_c

MODULES: List[Dict[str, Any]] = list(concepts_a.MODULES) + list(concepts_b.MODULES) + list(concepts_c.MODULES)

_BY_MODULE = (
    ("foundations", concepts_a.CONCEPTS[:4]),
    ("build", concepts_a.CONCEPTS[4:]),
    ("dynamic", concepts_b.CONCEPTS[:6]),
    ("loading", concepts_b.CONCEPTS[6:]),
    ("execution", concepts_c.CONCEPTS[:4]),
    ("hardening", concepts_c.CONCEPTS[4:11]),
    ("forensics", concepts_c.CONCEPTS[11:]),
)

CONCEPTS: List[Dict[str, Any]] = []
for _module_id, _items in _BY_MODULE:
    for _concept in _items:
        _concept["module"] = _module_id
        _concept["order"] = len(CONCEPTS) + 1
        for _i, _action in enumerate(_concept["see"]):
            _action["id"] = "%s.%d" % (_concept["id"], _i + 1)
        CONCEPTS.append(_concept)

; SPDX-License-Identifier: AGPL-3.0-or-later
;
; Solidity SAST queries for Pencheff (Phase 2.3 seed sub-pack).
;
; Each capture name MUST match a rule id in ./rules.json. The loader
; cross-references at scan time and emits a finding per capture.
;
; Hand-curated by the Pencheff team. AI-generated additions will land
; under a sibling ``queries_synth.scm`` (one tree-sitter Query per
; file so a flaky generator can't break the hand-curated set) and be
; merged at load time.

;
; CWE-477 — authorization decision via tx.origin (vulnerable to
; phishing-driven contract calls).
;
(member_expression
  object: (identifier) @_obj
  property: (property_identifier) @_prop
  (#eq? @_obj "tx")
  (#eq? @_prop "origin")) @solidity-tx-origin-auth

;
; CWE-330 — block.timestamp / block.number used as a randomness
; source. Miners can manipulate both within a window.
;
(member_expression
  object: (identifier) @_blk
  property: (property_identifier) @_field
  (#eq? @_blk "block")
  (#match? @_field "^(timestamp|number|difficulty|prevrandao)$")
) @solidity-weak-randomness

;
; CWE-477 — `selfdestruct` was deprecated in Solidity 0.8.18+ and
; the EVM behaviour around it has changed across hardforks.
;
((call_expression
  function: (identifier) @_fn)
 (#eq? @_fn "selfdestruct")) @solidity-deprecated-selfdestruct

;
; CWE-252 — low-level `.call` whose return value is discarded.
; Catches the common pattern ``addr.call{value: x}("");`` used as a
; fire-and-forget transfer; leads to silent failures.
;
(expression_statement
  (call_expression
    function: (member_expression
      property: (property_identifier) @_method
      (#match? @_method "^(call|delegatecall|staticcall|callcode)$")
    ))) @solidity-unchecked-low-level-call

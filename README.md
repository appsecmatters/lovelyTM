# litetm
Lightweight threat modeling tool

TODO explain STRIDE business first

## Not implemented yet

* Online help in the Business Scenario and Technical Scenario modals

* Wizard to ask to fill (e.g. TechnicalScenarios optional in case of Low business impact)

* Counter measures
CounterMeasure: title as String, description as String, technicalScenarios as list of technicalScenario, technicalDifficulty as Difficulty, logisticsDifficulty as Difficulty

* Reusing scenarios for different interactions/stride letters

* Importing an exported JSON file instead of using sequence diagram markdown as input

* Diff between an exported JSON file and a new sequence diagram: ask to update only the modified Interactions

## Build history

* Initial Claude build with version 0.11 of specs: it took 15 minutes. UI description was missing section 2 Attack Scenarios
* Version 0.12: it took 4 minutes. UI description now contains section 2 Attack Scenarios, validate markdown before closing import modal
* Version 0.13: it took x minutes. Color arrows + export sequence digram in JSON.

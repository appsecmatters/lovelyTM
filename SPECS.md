Version 0.27

# High level description

A webpage that takes in input a markdown sequence diagram, displays it and allows to annotate the arrows with security concerns.

The structure of those security concerns is described in the data model section.
The business logic section describes how they are combined to produce the risk scores.
The UI section details how the user provides them and how the resulting risk scores are displayed.

Persistence is provided by downloading the data structure in a JSON file.

# Tech stack

No backend, just a javascript frontend that can run directly in the browser.
No database, just JSON in memory.
Minimal dependencies.

# Data model

Actor: name as String, parsed from the input sequence diagram

Severity: Enum (ordered) with values None, Low, Medium, High

Difficulty: Enum (ordered) with values NA, Low, Low-Medium, Medium, Medium-High, High

BusinessRisk: Enum (ordered) with values NA, None, Low, Medium, High, Critical

BusinessScenario: title as String, description as String, businessImpact as Severity

TechnicalScenario: title as String, description as String, technicalDifficulty as Difficulty, logisticsDifficulty as Difficulty

BusinessImpactSTRIDE: s as list of BusinessScenario, t as list of BusinessScenario, r as list of BusinessScenario, i as list of BusinessScenario, d as list of BusinessScenario, e as list of BusinessScenario

AttackDifficultySTRIDE: s as list of TechnicalScenario, t as list of TechnicalScenario, r as list of TechnicalScenario, i as list of TechnicalScenario, d as list of TechnicalScenario, e as list of TechnicalScenario

ResultingBusinessRisks: s as BusinessRisk, t as BusinessRisk, r as BusinessRisk, i as BusinessRisk, d as BusinessRisk, e as BusinessRisk

Interaction: source as Actor, destination as Actor, businessImpact as BusinessImpactSTRIDE, attackDifficulty as AttackDifficultySTRIDE

# Business logic

## STRIDE mappings

s: Spoofing
t: Tampering
r: Repudiation
i: Information Disclosure
d: Denial of Service
e: Elevation of Privilege

## Scoring methodology

The risk score is computed by combining the buiness impact and the attack difficulty as in the BusinessRiskMatrix.
The attack difficulty is computed by combining the technical and logistics difficulties as in the DifficultyMatrix.
This logic is isolated in `risk_scoring.js`.

BusinessRiskMatrix:
| Business Impact / Attack Difficulty | NA | Low | Low-Medium | Medium | Medium-High | High |
| ----------------------------------- | -- | --- | ---------- | ------ | ----------- | ---- |
| None | None | None | None | None | None | None |
| Low | Low | Low | Low | Low | Low | Low |
| Medium | NA | Medium | Medium | Medium | Low | Low |
| High | NA | Critical | Critical | High | Medium | Medium |

DifficultyMatrix:
| Technical / Logitiscs | Low | Low-Medium | Medium | Medium-High | High |
| --------------------- | --- | ---------- | ------ | ----------- | ---- |
| Low | Low | Low-Medium | Medium | Medium-High | High |
| Low-Medium | Low-Medium | Low-Medium | Medium | Medium-High | High |
| Medium | Medium | Medium | Medium-High | Medium-High | High |
| Medium-High | Medium-High| Medium-High | Medium-High | High | High |
| High | High | High | High | High | High |

## Processing

An Interaction is built for each arrow in the sequence diagram, with the source and destination Actors.
A list of BusinessScenario and a list of TechnicalScenario is linked to this Interaction for the 6 s, t, r, i, d, e components.
The UI section describes how the user provides those 2 lists.

For each Interaction, a ResultingBusinessRisks is computed using the same logic for its s, t, r, i, d and e components.
Only the algorithm for the s component is described below, for the other components just replace s by t,r,i,d or e:
1. Iterate over the s list of businessImpact and find the highest severity. Name it maxImpact. If list is empty, return NA.
2. Iterate over the s list of attackDifficulty, compute difficulty according to DifficultyMatrix and find the lowest difficulty. Name it minDifficulty. If list is empty, return NA.
3. Compute BusinessRisk from maxImpact and minDifficulty using BusinessRiskMatrix.
4. Store it in s of ResultingBusinessRisks

# UI

First line: 
* a button "Import sequence diagram" that opens a modal where the user pastes the Markdown of a sequence diagram.
When the modal is closed, the markdown is rendered in the main panel.
If there is a syntax error, the modal cannot be closed.
* a button "Import existing JSON" which open a previously exporting JSON. It loads the markdown from the `sequenceDiagram` field and instatiates the Interaction objects from the `interactions` field
* a button "Export" which opens a modal asking for filename and then triggers the workflow described in the Persistence section
* a button "Crash Course" which opens a modal with a HTML view of `crash_course.md`. HTML new lines should match the empty lines of md file. Include online help
* a button "Risk scoring" which opens a modal with a HTML view of the 2 tables BusinessRiskMatrix and DifficultyMatrix

Main panel: the rendered sequence diagram
Just above it: a label "Coverage score" with its value corresponding to the percentage (with 1 decimal) of ResultingBusinessRisks that are different from NA.

Under each arrow of the sequence diagram, display the 6 letters S T R I D E separated by a whitespace.
When clicking on any of those 6 letters, open a modal.

Its title is the STRIDE mapping corresponding to the letter, followed by the online help.
The modal has 3 sections one below the other: Business Impact Scenarios, Attack Scenarios, Resulting Risk.

Section 1 shows the list of BusinessScenario, displaying its title, an Edit button and a Trash button to update or delete this entry.
There is a + button (with message Add Business Impact Scenario) below the list to insert a BusinessScenario which opens a submodal.
Next to this button, display a small help icon and when mouse is over it, show the corresponding message "Supposing such attack is possible, what would be the business impact?"
Same icon and content is displayed next to the submodal window title. Submodal window title is "Business Impact scenario for " + STRIDE mapping.
Submodal asks for title, description, businessImpact (dropdown of Severity fields). When closed, a BusinessScenario is built.

Section 2 shows the list of TechnicalScenario, displaying its title, an Edit button and a Trash button to update or delete this entry.
There is a + button below the list to insert a TechnicalScenario which opens a submodal.
Next to this button, display a small help icon and when mouse is over it, show the corresponding message "Estimate the complexity to execute such attack"
Same icon and content is displayed next to the submodal window title. Submodal window title is "Attack scenario for " + STRIDE mapping.
Submodal asks for title, description, technicalDifficulty (dropdown of Difficult fields), logisticsDifficulty (dropdown of Difficult fields). When closed, a TechnicalScenario is built.

Section 3 is a label called Resulting Risk followed by the computed BusinessRisk with the color corresponding to coloring results.

Closing the modal updates businessImpact and attackDifficulty of this letter for this Interaction.
And then triggers a coloring results for this letter of this Interaction, followed by updating the coverage score.
If businessImpact is not NA but businessRisk is NA, add a question mark below this letter.

## Coloring results

Apply the risk scoring algorithm described in subsection Processing of Business logic.
Change the color of the letter depending on the BusinessRisk value computed:
* NA: black
* None: Green
* Low: light yellow
* Medium: orange
* High: red
* Critical: purple

Update the color of the text above the corresponding arrow by using the color of the highest business risk letter.

## Stylesheet

Something simple like the bootstrap CSS.

## Online help

Next to the word Spoofing, Tampering, Repudation, Information Disclosure, Denial of Serivce, Elevation of Privilege:
display a small help icon and when mouse is over it, show the corresponding definition loaded from `STRIDE_definitions.md`

# Persistence

Build a JSON with:
* the sequence diagram markdown as String in a sequenceDiagram field
* the list of Interaction objects and a full copy of their members as described in the Data model section.

Generate from this JSON a file called {filename}.json and have the browser download it.

# Testing

Generate in `test_all_risk_scores.js` an explicit list of all the possible values of (technical difficulty, logistics difficulty, business impact) and compute the corresponding business riks according to BusinessRiskMatrix and DifficultyMatrix.
Make sure:
* None business impact always returns None
* Low business impact always returns Low
* Medium business impact always return Low, Medium or NA
* High business impact returns at least Medium or NA

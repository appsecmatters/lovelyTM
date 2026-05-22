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

Severity: Enum (ordered) with values Low, Medium, High

Difficulty: Enum (ordered) with values Low, Low-Medium, Medium, Medium-High, High

BusinessRisk: Enum (ordered) with values Low, Medium, High, Critical

BusinessScenario: title as String, description as String, businessImpact as Severity

TechnicalScenario: title as String, description as String, technicalDifficulty as Difficulty, logisticsDifficulty as Difficulty

CounterMeasure: title as String, description as String, technicalScenarios as list of technicalScenario, technicalDifficulty as Difficulty, logisticsDifficulty as Difficulty

BusinessImpactSTRIDE: s as list of BusinessScenario, t as list of BusinessScenario, r as list of BusinessScenario, i as list of BusinessScenario, d as list of BusinessScenario, e as list of BusinessScenario

AttackDifficultySTRIDE: s as list of TechnicalScenario, t as list of TechnicalScenario, r as list of TechnicalScenario, i as list of TechnicalScenario, d as list of TechnicalScenario, e as list of TechnicalScenario

ResultingBusinessRisks: s as BusinessRisk, t as BusinessRisk, r as BusinessRisk, i as BusinessRisk, d as BusinessRisk, e as BusinessRisk

Interaction: source as Actor, destination as Actor, businessImpact as BusinessImpactSTRIDE, attackDifficulty as AttackDifficultySTRIDE

# Business logic

The risk score is computed by combining the buiness impact and the attack difficulty as in the BusinessRiskMatrix.
The attack difficulty is computed by combining the technical and logistics difficulties as in the DifficultyMatrix

BusinessRiskMatrix:
| Business Impact / Attack Difficulty | Low | Low-Medium | Medium | Medium-High | High |
| Low | Low | Low | Low | Low | Low |
| Medium | Medium | Medium | Medium | Low | Low |
| High | Critical | Critical | High | Medium | Medium |

Difficulty Matrix:
| Technical / Logitiscs | Low | Low-Medium | Medium | Medium-High | High |
| Low | Low | Low-Medium | Medium | Medium-High | High |
| Low-Medium | Low-Medium | Low-Medium | Medium | Medium-High | High |
| Medium | Medium | Medium | Medium-High | Medium-High | High |
| Medium-High | Medium-High| Medium-High | Medium-High | High | High |
| High | High | High | High | High | High |

For each Interaction, a ResultingBusinessRisks is computed using the same logic for its s, t, r, i, d and e components.
Only the algorithm for the s component is described below, for the other components just replace s by t,r,i,d or e:
1. Iterate over the s list of businessImpact and find the highest severity. Name it maxImpact
2. Iterate over the s list of attackDifficulty, compute difficulty according to DifficultyMatrix and find the lowest difficulty. Name it minDifficulty
3. Compute BusinessRisk from maxImpact and minDifficulty using BusinessRiskMatrix
4. Store it in s of ResultingBusinessRisks

NB: CounterMeasure ignored for the moment

# UI

TODO explain modal

TODO explain results displayed

Stylesheet: something basic like the bootstrap CSS

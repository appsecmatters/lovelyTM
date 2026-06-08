# lovelyTM

A lovely and lightweight threat modeling tool.

## CONCEPT

Hopefully this is not yet another threat modeling tool as the concept is based on **strong differentiators**:
* based on [Microsoft STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats#stride-model), but **focusing first on business risks** to make it less verbose
* visual heatmap of the most sensitive areas
* help produce a prioritized short-list of most security requirements, rather than a long inventory of threats 
* using regular [sequence diagrams](https://en.wikipedia.org/wiki/Sequence_diagram) to minimize the learning curve vs specific modeling, but defining them as code to enable reusability and machine
* browser-only code to avoid storing in a backend, persistence achieved via importing/exporting human readable JSON files 

## HOWTO

Sequence diagram https://mermaid.js.org/syntax/sequenceDiagram.html
Or exported JSON file

Explain ? and !

## DEPLOYMENT

You can use direclty lovelytm.appsecmatters.com: no need to worry about sensitive information, all the processing is handled direclty by the browser.
Or self-host this folder with the static web server of your choice.

## ROADMAP

Coming soon:
* Diff feature between an exported JSON file and a new sequence diagram: ask to update only the modified Interactions
* Reusing scenarios between different Interactions or STRIDE letters

## CONTRIBUTING

Either file in an issue or propose a pull request with modifications in `SPECS.md`.
(Pull requests changing code directly will be ignored.)

## ANY QUESTION?

Contact lovelytm@appsecmatters.com

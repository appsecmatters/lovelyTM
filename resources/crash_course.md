### Goal: Identify security risks in the interactions between the components and prioritize what requires fixing

* Have a rather exhaustive methodology to list risks: STRIDE from Microsoft
* Compute a score for those risks
* Find security requirements (either a technical solution, a process or a doc) to reduce the severity of the most significant risks

### Customized STRIDE methodology

* 6 families of threats
  * Spoofing
  * Tampering
  * Repudiation
  * Information disclosure
  * Denial of service
  * Escalation of privilege

* Draw a high level diagram of the various components

* For every interaction between 2 components
  * Suppose a threat can be exploited (i.e. an attack exists)
  * Estimate the business impact of such attack (Low, Medium, High)
  * Estimate the complexity to execute such attack both from a technical and logistics point of view
  * Risk score computed according to tables in Risk Scoring

### What's next

* Build a list of security requirements prioritized by risk reduction vs implementation effort
* Restart the threat modeling loop to update risks when new components or features or added

# Web Attack Lab Design

## Status

Draft for capstone planning and Claude cross-review.

This document captures the current product direction. GitHub issues will be created later after cross-checking the plan with Claude and reviewing the reference project shared by Romain.

## Product Summary

The project is a Docker-based web attack practice platform for university students who are beginning to learn web security.

Existing tools such as DVWA are useful for hands-on practice, but they can be difficult for beginners because they often show whether an attack worked without clearly explaining how the user's input moved through the server, browser, database, or vulnerable code path. This project keeps the direct attack practice style of DVWA, then adds beginner-friendly feedback after each attempt.

The core product idea is:

> A beginner-focused web attack practice platform that lets users try attacks directly, visualizes successful attacks, and diagnoses failed payloads through a Lens-style feedback feature.

## Target User

The primary user is a university student who is learning web security for the first time.

This is intentionally close to the developer's own current learning position. The project should help that user move from "I can run an attack payload" to "I understand why this payload did or did not become a valid attack."

## Differentiation From DVWA

DVWA is mostly organized around attack names and direct vulnerable pages. This project should preserve that practice-first quality, but improve the learning feedback.

Key differences:

- Attack categories remain visible so users understand the learning path.
- Each lab should feel like a real web feature, such as login, search, profile lookup, posting, or request submission.
- Successful attacks trigger a visualization of the processing flow.
- Failed attacks trigger Lens feedback that explains why the payload did not work.
- README content provides short prerequisite education before users begin.

The platform should feel like an extension of DVWA, not a replacement for a textbook, a generic CTF system, or an AI tutor.

## Core Learning Flow

Each lab follows a practice-first flow:

1. The user selects an attack category and difficulty.
2. The user interacts with a realistic web feature and submits an attack input.
3. The backend evaluates the attempt.
4. If the attack succeeds, the app shows the result and a visualization.
5. If the attack fails, the app shows Lens feedback.
6. The user retries with a better understanding of what was missing.

Success and failure have separate teaching roles.

### Success: Visualization

When an attack succeeds, the app should not rely mainly on text explanation. The success path should show how the input was processed.

The visualization should show:

- The user's input.
- The relevant request or browser event.
- The server route or browser processing step.
- The vulnerable transformation, such as query construction, HTML insertion, command construction, or authorization lookup.
- The final result that proves the attack succeeded.
- The vulnerable code line or block that made the attack possible.

This should be closer to a structured flow visualization than a full Python Tutor clone. The app does not need to trace every executed line. Each lab can define a static flow template, then insert the user's input, generated query or command, and result.

### Failure: Lens

Lens is focused on failed attacks only.

The user can use Lens after submitting a payload that did not work. Lens diagnoses the attempted input and explains which condition was missing.

Examples:

- SQL Injection: the input contains a quote but does not create a condition that changes authentication logic.
- Command Injection: the input does not include a valid command separator for the lab's shell context.
- Reflected XSS: the input is placed in a context where the chosen payload cannot execute.
- CSRF: the request does not match the method or required parameters of the target action.
- IDOR: the user did not request another user's resource or the chosen identifier is not meaningful in the lab.

Lens should be rule-based for the MVP. It should not depend on AI to explain the user's mistake, because one motivation for the project is to make beginner understanding possible without requiring AI assistance.

Lens is inspired by Error Lens and the previous loupe/lens-style product thinking: it should make the important problem location visible near the user's attempted input. It should not duplicate the success visualization role.

## Candidate Attack Scope

The current candidate scope is:

- SQL Injection
- Command Injection
- Reflected XSS
- Stored XSS
- DOM XSS
- CSRF
- IDOR

This scope is not final. It should be refined through a GitHub issue.

The current recommendation is to begin with a small representative set, then expand once the common Lens and visualization structure is stable. SQL Injection, Reflected XSS, and IDOR are strong first candidates because they cover database flow, browser execution flow, and authorization flow.

## Difficulty Direction

The current direction is two levels:

- Easy: the vulnerable behavior is obvious and the lab focuses on learning a representative payload structure.
- Medium: the lab includes partial filtering, incomplete defense, or a slightly more realistic result-based success condition.

This borrows some ideas from DVWA's Low/Medium/High style, but intentionally avoids expanding to a High level during the first phase.

This design is not final. Difficulty design should be refined through a GitHub issue.

## Technology Direction

The main stack should be:

- FastAPI for the backend.
- React for the frontend.
- A database such as SQLite or PostgreSQL for labs that need stored data.
- Docker and Docker Compose for local execution.

Python/FastAPI is the main implementation path because it is familiar to the team and easier to explain to beginner learners. React supports the interactive lab UI, Lens panel, and visualization surfaces.

PHP should not be a separate runtime service in the MVP. It can appear as comparison code in learning materials, especially when explaining how DVWA-style PHP vulnerabilities map to the FastAPI version.

## Safety Model

The final result should be a local Docker-based practice environment.

The app intentionally contains vulnerable behavior, so the default product should not be deployed as a public server. The README and first app screen should both make this clear.

Command Injection and similar risky labs should be realistic but controlled:

- Run only inside Docker.
- Prefer allowlisted commands or a limited shell environment.
- Keep meaningful files inside a lab-only directory.
- Limit output to what the lab needs.
- Avoid giving users access to host resources.

The goal is controlled realism, not a fake simulation and not an unsafe open shell.

## README Education

README should serve as a short prerequisite learning document, not only an installation guide.

For each covered attack, README should include:

- A direct definition.
- Why the vulnerability occurs.
- A simple representative example.
- The basic defense idea.
- Safety warnings about using the project only in the intended Docker environment.

The writing should be clear enough for a beginner university student. The developer plans to write these explanations while studying, so the text should reflect the learner's perspective instead of sounding like a dense textbook.

## Module Architecture Direction

Use a hybrid module structure.

Shared parts:

- Lab list and category navigation.
- Common result format.
- Common Lens feedback shape.
- Common visualization data shape.
- Common UI components for attempts, failure feedback, and success visualization.

Attack-specific parts:

- Vulnerable routes.
- Lab-specific data models.
- Success and failure rules.
- Payload diagnosis rules.
- Flow templates.
- Code snippets and comparison examples.

This avoids two extremes:

- Fully hardcoded pages would be fast at first but difficult to expand.
- A fully metadata-driven lab engine would be flexible but too heavy before the attack behavior is well understood.

The exact boundary should be discussed in a GitHub issue.

## Out Of Scope For The First Phase

The following are intentionally excluded from the first phase:

- User accounts.
- Progress tracking or scoring.
- Public deployment of the vulnerable app.
- AI-generated failure explanations.
- A full Python Tutor-style runtime tracer.
- A separate PHP execution service.
- Finalizing every attack scenario before the common lab structure is stable.

## GitHub Issues To Create After Cross-Review

### Discuss Module Boundary For Adding New Attack Labs

Purpose:

Decide how far each attack lab should be modularized.

Open questions:

- Which parts should be metadata-driven?
- Which parts should remain custom code per attack?
- How should Easy and Medium difficulty variants be represented?
- How much of the success visualization should be static versus filled from user input?
- How should Lens rules be attached to each lab?

Initial recommendation:

Keep Lens UI, visualization UI, result format, and lab metadata common. Implement vulnerable behavior separately for each attack type.

### Discuss Attack Scope And Difficulty Levels

Purpose:

Define the final attack scope and difficulty design.

Open questions:

- Which attacks must be included in the first public version?
- Should every attack have both Easy and Medium levels?
- Should success conditions differ by difficulty?
- Should some attacks wait until the Lens and visualization flow is stable?
- How much should the project prioritize breadth of attacks versus depth of explanation?

Initial recommendation:

Start with a small set of representative attacks, then expand after the shared structure is stable.

## Acceptance Criteria For The Design

The design is successful if:

- A beginner can understand the product goal without needing prior DVWA experience.
- Success visualization and failure Lens have clearly separate roles.
- The MVP can be built without accounts, scoring, public hosting, or AI feedback.
- Future attack labs can be added without rewriting the whole frontend.
- Docker safety boundaries are visible in both documentation and the app.
- The design can be turned into GitHub issues after Claude cross-review.

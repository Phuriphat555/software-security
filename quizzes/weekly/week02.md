# Weekly Quiz — Week 2 (Secure SDLC, Tooling & Fuzzing)

**~10 min · 6 questions · low-stakes** (lowest scores dropped). Individual.

**Name:** Phuriphat Chantiuaong  **Student ID:** 6631503034

## MCQ (5 × 1)
1. **SAST** analyzes:
   b) source code without running it
2. The tool type that finds **hardcoded secrets** in code/history is:
   c) secret scanning
3. Coverage-guided **fuzzing** finds bugs by:
   b) mutating inputs and watching for new paths/crashes
4. A **false positive** is:
   b) a flagged finding that is not actually a bug
5. **SCA** checks:
   b) dependencies for known CVEs

## Short answer (1 × 3)
6. Name **one** bug SAST would catch that DAST would not — and one DAST would catch that SAST would not.
answer
SAST: hardcoded passwords/secrets or insecure code patterns that can be detected by examining the source code.
DAST: a runtime vulnerability such as an authentication bypass or an HTTP response issue that only appears when the application is running.
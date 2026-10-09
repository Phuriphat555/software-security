# Threat Model — <Sample Flask App>

## 1. Data-flow diagram
(Insert your DFD image. Mark trust boundaries with dashed lines.)
= ![alt text](image-1.png)

## 2. Elements & trust boundaries
Element	                 Type (process/store/entity/flow)	       Trust boundary crossed?
Web client	                     external entity	                yes (Internet → app)
Flask app	                         process	                    yes (Internet → app)
SQLite DB (notes.db)	             data store	                    yes (app → data store)
uploads/ store	                      ata store	                    yes (app → file store)
 
## 3. STRIDE analysis
![alt text](image.png)

## 4. Top 5 risks (likelihood × impact) + mitigation
1. Path Traversal / Arbitrary File Write — Critical
Likelihood: High
Impact: High
Risk: Critical
The /upload endpoint uses the client-controlled f.filename when saving a file. An attacker may manipulate the filename using path traversal such as ../ and cause the application to write outside the intended uploads/ directory.
Mitigation: Use secure_filename(), allow-list file extensions, generate server-side filenames, and ensure uploaded files are stored only in the intended directory.

2. Missing Authentication on /notes — Critical
Likelihood: High
Impact: High
Risk: Critical
The /notes endpoint accepts an owner value directly from the client without authentication. An attacker can therefore claim to be another owner.
Mitigation: Require authentication and obtain the owner identity from the authenticated session/token instead of trusting the client-provided owner.

3. Missing Authorization — High
Likelihood: Medium
Impact: High
Risk: High
The application may allow a user to access or modify resources belonging to another user if ownership is not checked.
Mitigation: Perform server-side authorization checks for every protected note and file operation.

4. Information Disclosure — Medium
Likelihood: Medium
Impact: Medium
Risk: Medium
The /upload endpoint echoes the resolved save path in its response. This can reveal information about the server's file-system structure.
Mitigation: Return only a safe file identifier or filename and never expose the server's absolute file-system path.

5. Denial of Service Through Uploads — Medium
Likelihood: Medium
Impact: Medium
Risk: Medium

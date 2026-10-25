# TrustVault — Secure Document Sharing Platform

TrustVault is a secure document-sharing application designed around server-side authorization. Instead of trusting the React interface to decide who can access a document, the application uses Supabase authentication, PostgreSQL Row-Level Security (RLS), private storage, and server-side functions to enforce access controls.

## Live Demo

* **Live Application:** https://trustvault-delta-ten.vercel.app/
* **GitHub Repository:** https://github.com/saiprasanna2005/TrustVault

## Technology Stack

* **Frontend:** React, Vite, TypeScript
* **Styling:** Tailwind CSS 4
* **Authentication:** Supabase Auth
* **Database:** Supabase PostgreSQL
* **Authorization:** PostgreSQL Row-Level Security (RLS)
* **File Storage:** Supabase private Storage
* **Server-side Operations:** Supabase Edge Functions
* **Testing:** Vitest and PGlite

## Features

* User authentication
* Document upload and download
* Document sharing with other users
* Permission management
* Access revocation
* Database-level access control using RLS
* Private document storage
* Server-side functions for protected operations
* Automated unit and database-policy simulation tests

## Live Application Status

The application has been deployed to Vercel.

The following features have been tested manually in the deployed application:

| Feature                  | Verification |
| ------------------------ | ------------ |
| Application deployment   | Passed       |
| Login and authentication | Passed       |
| Document upload          | Passed       |
| Document download        | Passed       |
| Document sharing         | Passed       |
| Permission management    | Passed       |
| Access revocation        | Passed       |

These results represent manual application checks. They do not, by themselves, establish that every database policy, storage policy, or server-side security control has passed independent testing against the hosted Supabase project.

## 1. How It Works

TrustVault separates the user interface from the security decisions.

### Authentication

Supabase Auth manages user authentication and provides the authenticated user identity.

### Authorization

PostgreSQL Row-Level Security policies restrict database operations according to the authenticated user's permissions.

The frontend is not treated as the security boundary. Protected operations must be authorized by the database or trusted server-side code.

### Private Document Storage

Documents are stored in private Supabase Storage rather than being made publicly accessible through a public bucket.

Access to files must be governed by the application's authorization rules and the relevant storage policies.

### Server-Side Operations

Supabase Edge Functions handle protected operations that require trusted server-side logic.

The Supabase service-role key must remain on the server and must never be included in frontend code or publicly committed files.

### Access Revocation

When a document owner's sharing permissions are revoked, the application is intended to prevent the affected user from continuing to access the document through protected operations.

The effectiveness of this control depends on the database policies, storage policies, and server-side authorization checks being correctly configured.

## 2. Project Structure

The repository contains the frontend application, Supabase configuration, database migrations, Edge Functions, and tests.

```text
TrustVault/
├── public/
├── src/
│   ├── components/
│   ├── pages/
│   ├── lib/
│   └── ...
├── supabase/
│   ├── config.toml
│   ├── migrations/
│   │   ├── 0001_core_schema.sql
│   │   ├── 0002_security_functions_and_rls.sql
│   │   ├── 0003_audit_integrity.sql
│   │   └── 0004_private_storage.sql
│   └── functions/
├── tests/
├── .gitignore
├── package.json
├── package-lock.json
├── vite.config.ts
└── README.md
```

The exact contents of individual folders may change as the project develops.

## 3. Run Locally

### Prerequisites

Install the following tools:

* Node.js and npm
* Git
* A Supabase project
* Supabase CLI, if you need to manage migrations or deploy Edge Functions

### Step 1: Clone the Repository

```bash
git clone https://github.com/saiprasanna2005/TrustVault.git
cd TrustVault
```

### Step 2: Install Dependencies

```bash
npm install
```

### Step 3: Configure Environment Variables

Create a `.env` file in the project root and configure the Supabase URL and publishable key using the variable names expected by the application.

For example:

```env
VITE_SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
VITE_SUPABASE_ANON_KEY=YOUR_SUPABASE_PUBLISHABLE_OR_ANON_KEY
```

Replace the example values with the appropriate values from your Supabase project.

Use the exact environment variable names expected by the existing application if they differ from these examples.

**Important security rules:**

* A Supabase publishable key, or legacy `anon` key, may be used in the frontend when database and storage access are properly protected by RLS and other applicable policies.
* A Supabase `service_role` key or secret key is highly privileged. Never expose it in frontend code, GitHub, or Vercel frontend environment variables.
* Edge Functions should receive privileged credentials through their server-side environment.
* Keep local environment files out of Git by using `.gitignore`.

### Step 4: Start the Development Server

```bash
npm run dev
```

Open the local URL printed by Vite, usually:

```text
http://localhost:5173
```

### Step 5: Build for Production

```bash
npm run build
```

Vite generates the production build in the `dist/` directory.

## 4. Testing

TrustVault includes unit tests and database-policy simulation tests.

Run the test suite with:

```bash
npm test
```

To run the production build:

```bash
npm run build
```

If the project provides separate scripts for database-policy simulation or live security integration tests, use the corresponding scripts defined in `package.json`.

### Local Verification Results

The following local results were recorded during development:

| Check                                             | Result                    |
| ------------------------------------------------- | ------------------------- |
| Unit tests                                        | 10 passed                 |
| PGlite database-policy simulation tests           | 27 passed                 |
| Combined recorded local test count                | 37 passed                 |
| Production build                                  | Passed                    |
| Deno type check                                   | Passed                    |
| Frontend bundle scan for service-role key strings | No matching strings found |

The mutation tests also failed as expected when security protections were deliberately broken during testing.

**Testing limitation:** PGlite-based tests simulate database behavior locally. They do not prove that the hosted Supabase project's actual RLS policies, Storage policies, authentication configuration, or deployed Edge Functions are secure.

Live Supabase security integration tests have not been confirmed as executed. Do not interpret the local test results as proof that those live security tests passed.

## 5. Deployment

### Frontend Deployment

The frontend is deployed using Vercel.

Live URL:

https://trustvault-delta-ten.vercel.app/

To deploy your own copy:

1. Push the project to a GitHub repository.
2. Import the repository into Vercel.
3. Configure the required frontend environment variables.
4. Build using the project's configured Vite build command.
5. Deploy the application.
6. Test authentication, document operations, sharing, and permission changes.

Do not add Supabase service-role credentials to frontend environment variables.

### Supabase Configuration

The backend uses Supabase for authentication, database access, private file storage, and Edge Functions.

Database migrations are stored in:

```text
supabase/migrations/
```

Edge Functions are stored under:

```text
supabase/functions/
```

Apply the migrations and deploy the functions according to the project's Supabase configuration.

Before deploying to a new Supabase project, verify the database schema, RLS policies, Storage policies, function secrets, and allowed origins.

## 6. Security Considerations

TrustVault is designed around the following security principles:

* **Server-side authorization:** Security decisions must not depend solely on frontend checks.
* **Least privilege:** Users should receive only the access needed for their permitted operations.
* **Database protection:** RLS policies help restrict unauthorized database access.
* **Private storage:** Documents should not be exposed through unrestricted public access.
* **Secret management:** Privileged keys must remain on the server.
* **Permission revocation:** Revoked access must be enforced by the relevant authorization controls.
* **Verification:** Local simulation tests and live integration tests serve different purposes and should be reported separately.

A successful deployment or a passing local test suite does not automatically establish that every security requirement has been satisfied. Security claims should be supported by appropriate tests against the actual deployed configuration.

## 7. Verification Status

### Live Application Checks

The following checks were reported as manually tested on the deployed application:

| Check                        | Status |
| ---------------------------- | ------ |
| Vercel deployment accessible | Passed |
| Login and authentication     | Passed |
| Document upload              | Passed |
| Document download            | Passed |
| Document sharing             | Passed |
| Permission management        | Passed |
| Access revocation            | Passed |

### Automated and Local Verification

| Check                                                  | Status                                                               |
| ------------------------------------------------------ | -------------------------------------------------------------------- |
| Production build                                       | Passed                                                               |
| Unit tests                                             | 10 passed                                                            |
| PGlite database-policy simulation                      | 27 passed                                                            |
| Security mutation tests                                | Expected failures observed when protections were deliberately broken |
| Deno type checking                                     | Passed                                                               |
| Frontend bundle scan for service-role key strings      | No matching strings found                                            |
| Live Supabase security integration tests               | Not confirmed as executed                                            |
| Live Storage, PostgREST, and RLS security verification | Not confirmed as completed                                           |

The live application checks above are manual checks. The automated results are local development results. These categories are intentionally separated so that the README does not overstate the extent of security verification.

## 8. Known Limitations

* Local database simulation tests do not replace tests against the hosted Supabase project.
* Live security integration tests must be executed before claiming that the deployed backend has passed them.
* Security depends on the correctness of the database policies, Storage policies, authentication configuration, and Edge Function authorization logic.
* Deployment success alone does not guarantee security.
* Environment variables and secrets must be configured separately for local development and production.

## 9. Repository

GitHub:

https://github.com/saiprasanna2005/TrustVault

## 10. Final Note

TrustVault demonstrates a document-sharing architecture that uses authentication, database-level authorization, private storage, and server-side operations.

The project distinguishes between features manually verified in the deployed application and security checks that still require live integration testing.

---

# User Management Service

The User Management service handles user-related operations, including authentication, role-based access control (RBAC), and user management.

## Features
- User signup, login, and SSO (OIDC/SAML).
- Role-based access control (RBAC).
- User management (create, read, update, delete).

## Folder Structure
```
/user-management/
    README.md                # Documentation for the service
    api/                     # API endpoints for user management
    models/                  # Database models for users
    output/                  # Logs and audit trails
    rule-engine/             # Logic for evaluating RBAC rules
    rules/                   # JSON-based rules for roles and permissions
    tests/                   # Unit and integration tests
```

## API Endpoints
- `POST /users` - Create a new user.
- `GET /users` - Fetch all users.
- `PUT /users/:id` - Update user details.
- `DELETE /users/:id` - Delete a user.

## Data Models
- **User**:
  - `id`: Unique identifier for the user.
  - `name`: Full name of the user.
  - `email`: Email address of the user.
  - `role`: Role assigned to the user (e.g., admin, tenant_admin, security_analyst).

## Rules
- **role-based-access.json**:
  - Defines roles and permissions for the service.

## Output
- Logs and audit trails for user actions.

## Tests
- Test cases for user creation, fetching, updating, and deletion.
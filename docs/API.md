# API

The API is a REST-ful API that uses JSON for serialization and JWT for authentication.
CRUD operations are available for users, roles and permissions.

## Table of contents

-   [OpenAPI / Swagger](#openapi--swagger)
-   [Audit](#audit)
-   [Authentication](#authentication)
-   [Register](#register)
-   [Login](#login)
-   [Current](#current)
-   [Users](#users)
    -   [Create](#create)
    -   [Read](#read)
    -   [Update](#update)
    -   [Delete](#delete)
-   [Roles](#roles)
    -   [Create](#create-1)
    -   [Read](#read-1)
    -   [Update](#update-1)
    -   [Delete](#delete-1)
-   [Permissions](#permissions)
    -   [Create](#create-2)
    -   [Read](#read-2)
    -   [Update](#update-2)
    -   [Delete](#delete-2)
-   [Searching](#searching-3)
-   [Pagination](#pagination)
-   [Health](#health)

## OpenAPI / Swagger

OpenAPI and Swagger documentation is available via the `/swagger-ui/` endpoint.

## Audit

`Audit` entities are available via the following endpoints, if enabled:

-   `/api/v1/audits/`
-   `/api/v1/audits/{id}`

### Read

`Audit` entities can be retrieved by users with the appropriate authorizations.

#### Find a single audit log

Find a single `Audit` entity by its ID.

##### Request

```http
GET /api/v1/audits/{id}
Authorization: Bearer <access token here>
```

##### Response

```http
{
  "id": "49782333-21ec-4623-b708-6646c2c8535d",
  "userId": "AUTH-RS",
  "action": "Read",
  "resourceId": "CAN_CREATE_PERMISSION",
  "resourceIdType": "permissionName",
  "resourceType": "permission",
  "createdAt": "2023-08-07T00:24:31.334654836+00:00",
  "updatedAt": "2023-08-07T00:24:31.334654836+00:00"
}
```

#### Find all audit logs

Find all `Audit` entities, within the given `page` and `limit` query parameters.

##### Request

```http
GET /api/v1/audits/
Authorization: Bearer <access token here>
```

##### Response

```http
[
  {
    "_id": "49782333-21ec-4623-b708-6646c2c8535d",
    "userId": "AUTH-RS",
    "action": "Read",
    "resourceId": "CAN_CREATE_PERMISSION",
    "resourceIdType": "permissionName",
    "resourceType": "permission",
    "createdAt": "2023-08-07T00:24:31.334654836+00:00",
    "updatedAt": "2023-08-07T00:24:31.334654836+00:00"
  },
  ...
]
```

## Authentication

Authentication is handled using JSON Web Tokens (JWT). The following endpoints are available:

-   `/api/v1/authentication/register/`
-   `/api/v1/authentication/login/`
-   `/api/v1/authentication/refresh/`
-   `/api/v1/authentication/current/`

### Register

Registering an account will create a new `User` entity and provide it with the `DEFAULT` role. Passwords will be hashed
using [argon2](https://en.wikipedia.org/wiki/Argon2) and a custom salt.

#### Request

```http
POST /api/v1/authentication/register/
{
  "username": "example",
  "email": "example@codedead.com",
  "firstName": "Jane",
  "lastName": "Doe",
  "password": "password"
}
```

#### Response

```http
200 OK
```

### Login

Logging in provides a `Bearer` access token that can be used to authenticate other requests that require certain
permissions. This access token should be added to the `Authorization` HTTP header for all endpoints that require
authentication and authorization.

#### Request

```http
POST /api/v1/authentication/login/
{
  "username": "example",
  "password": "password"
}
```

#### Response

```http
{
  "token": "Bearer access token here"
}
```

### Current

The current `User` entity can be retrieved using the access token that was obtained after logging in.

#### Request

```http
GET /api/v1/authentication/current/
Authorization: Bearer <access token here>
```

#### Response

```http
{
  "id": "d594989b-48bd-43d8-ab3e-d28671f145e6",
  "username": "admin",
  "email": "test@example.com",
  "firstName": "Test",
  "lastName": "Test",
  "roles": [
    {
      "id": "16a639cc-2240-4d2f-8def-bea0a729dd9e",
      "name": "DEFAULT",
      "description": "The default role",
      "permissions": [
        {
          "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
          "name": "CAN_UPDATE_SELF",
          "description": "The ability to update your own user"
        }
      ]
    }
  ]
}
```

## Users

`User` entities can be managed using the following CRUD endpoints:

-   `/api/v1/users/`
-   `/api/v1/users/{id}`

### Create

`User` entities can be created by other users with the appropriate authorizations.

#### Request

```http
POST /api/v1/users/
Authorization: Bearer <access token here>
{
  "username": "username",
  "email": "example@codedead.com",
  "firstName": "Jane",
  "lastName": "Doe",
  "password": "password",
  "roles": [
    "role id here"
  ]
}
```

#### Response

```http
{
  "id": "d594989b-48bd-43d8-ab3e-d28671f145e6",
  "username": "username",
  "email": "example@codedead.com",
  "firstName": "Jane",
  "lastName": "Doe",
  "enabled": true,
  "roles": [
    {
      "id": "role id here",
      "name": "DEFAULT",
      "description": "The default role",
      "permissions": [
        {
          "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
          "name": "CAN_UPDATE_SELF",
          "description": "The ability to update your own user"
        }
      ]
    }
  ]
}
```

### Read

`User` entities can be retrieved by other users with the appropriate authorizations.

#### Find a single user

Find a `User` entity by its ID.

##### Request

```http
GET /api/v1/users/{id}
Authorization: Bearer <access token here>
```

##### Response

```http
{
  "id": "d594989b-48bd-43d8-ab3e-d28671f145e6",
  "username": "username",
  "email": "example@codedead.com",
  "firstName": "Jane",
  "lastName": "Doe",
  "enabled": true,
  "roles": [
    {
      "id": "role id here",
      "name": "DEFAULT",
      "description": "The default role",
      "permissions": [
        {
          "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
          "name": "CAN_UPDATE_SELF",
          "description": "The ability to update your own user"
        }
      ]
    }
  ]
}
```

#### Find all users

Find all `User` entities, within the given `page` and `limit` query parameters.

##### Request

```http
GET /api/v1/users/
Authorization: Bearer <access token here>
```

##### Response

```http
[
  {
    "id": "d594989b-48bd-43d8-ab3e-d28671f145e6",
    "username": "username",
    "email": "example@codedead.com",
    "firstName": "Jane",
    "lastName": "Doe",
    "enabled": true,
    "roles": [
      {
        "id": "role id here",
        "name": "DEFAULT",
        "description": "The default role",
        "permissions": [
          {
            "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
            "name": "CAN_UPDATE_SELF",
            "description": "The ability to update your own user"
          }
        ]
      }
    ]
  },
  ...
]
```

#### Searching

Search for specific `User` entities with a given `text` query parameter.

##### Request

```http
GET /api/v1/users/?text=example
Authorization: Bearer <access token here>
```

##### Response

```http
[
  {
    "id": "d594989b-48bd-43d8-ab3e-d28671f145e6",
    "username": "username",
    "email": "example@codedead.com",
    "firstName": "Jane",
    "lastName": "Doe",
    "enabled": true,
    "roles": [
      {
        "id": "role id here",
        "name": "DEFAULT",
        "description": "The default role",
        "permissions": [
          {
            "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
            "name": "CAN_UPDATE_SELF",
            "description": "The ability to update your own user"
          }
        ]
      }
    ]
  },
  ...
]
```

### Update

`User` entities can be updated by other users with the appropriate authorizations.

#### Request

```http
PUT /api/v1/users/{id}
Authorization: Bearer <access token here>
{
  "username": "username",
  "email": "example@codedead.com",
  "firstName": "John",
  "lastName": "Doe",
  "roles": [
    "role id here"
  ],
  "enabled": true
}
```

#### Response

```http
{
  "id": "d594989b-48bd-43d8-ab3e-d28671f145e6",
  "username": "username",
  "email": "example@codedead.com",
  "firstName": "John",
  "lastName": "Doe",
  "enabled": true,
  "roles": [
    {
      "id": "role id here",
      "name": "DEFAULT",
      "description": "The default role",
      "permissions": [
        {
          "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
          "name": "CAN_UPDATE_SELF",
          "description": "The ability to update your own user"
        }
      ]
    }
  ]
}
```

### Delete

`User` entities can be deleted by other users with the appropriate authorizations.

#### Request

```http
DELETE /api/v1/users/{id}
Authorization: Bearer <access token here>
```

#### Response

```http
200 OK
```

Users can also remove themselves, if they have the appropriate authorizations:

#### Request

```http
DELETE /api/v1/users/{id}/self/
Authorization: Bearer <access token here>
```

#### Response

```http
200 OK
```

## Roles

`Role` entities can be managed using the following CRUD endpoints:

-   `/api/v1/roles/`
-   `/api/v1/roles/{id}`

### Create

#### Request

```http
{
  "name": "Role name",
  "description": "Role description",
  "permissions": [
    "permission id here"
  ]
}
```

#### Response

```http
{
  "id": "16a639cc-2240-4d2f-8def-bea0a729dd9e",
  "name": "Role name",
  "description": "Role description",
  "permissions": [
    {
      "id": "permission id here",
      "name": "CAN_UPDATE_SELF",
      "description": "The ability to update your own user",
      "createdAt": "2023-08-01T00:16:26.911565688+00:00",
      "updatedAt": "2023-08-01T00:16:26.911565688+00:00"
    }
  ],
  "createdAt": "2023-08-01T00:16:27.223266792+00:00",
  "updatedAt": "2023-08-01T00:16:27.223266792+00:00"
}
```

### Read

`Role` entities can be read by users with the appropriate authorizations.

#### Find a single role

##### Request

```http
GET /api/v1/roles/{id}
Authorization: Bearer <access token here>
```

##### Response

```http
{
  "id": "16a639cc-2240-4d2f-8def-bea0a729dd9e",
  "name": "Role name",
  "description": "Role description",
  "permissions": [
    {
      "id": "permission id here",
      "name": "CAN_UPDATE_SELF",
      "description": "The ability to update your own user",
      "createdAt": "2023-08-01T00:16:26.911565688+00:00",
      "updatedAt": "2023-08-01T00:16:26.911565688+00:00"
    }
  ],
  "createdAt": "2023-08-01T00:16:27.223266792+00:00",
  "updatedAt": "2023-08-01T00:16:27.223266792+00:00"
}
```

#### Find all roles

Find all `Role` entities, within the given `page` and `limit` query parameters.

##### Request

```http
GET /api/v1/roles/
Authorization: Bearer <access token here>
```

##### Response

```http
[
  {
    "id": "16a639cc-2240-4d2f-8def-bea0a729dd9e",
    "name": "Role name",
    "description": "Role description",
    "permissions": [
      {
        "id": "permission id here",
        "name": "CAN_UPDATE_SELF",
        "description": "The ability to update your own user",
        "createdAt": "2023-08-01T00:16:26.911565688+00:00",
        "updatedAt": "2023-08-01T00:16:26.911565688+00:00"
      }
    ],
    "createdAt": "2023-08-01T00:16:27.223266792+00:00",
    "updatedAt": "2023-08-01T00:16:27.223266792+00:00"
  },
  ...
]
```

#### Searching

Search for specific `Role` entities with a given `text` query parameter.

##### Request

```http
GET /api/v1/roles/?text=DEFAULT
Authorization: Bearer <access token here>
```

##### Response

```http
[
  {
    "id": "16a639cc-2240-4d2f-8def-bea0a729dd9e",
    "name": "Default",
    "description": "Role description",
    "permissions": [
      {
        "id": "permission id here",
        "name": "CAN_UPDATE_SELF",
        "description": "The ability to update your own user",
        "createdAt": "2023-08-01T00:16:26.911565688+00:00",
        "updatedAt": "2023-08-01T00:16:26.911565688+00:00"
      }
    ],
    "createdAt": "2023-08-01T00:16:27.223266792+00:00",
    "updatedAt": "2023-08-01T00:16:27.223266792+00:00"
  },
  ...
]
```

### Update

`Role` entities can be updated by users with the appropriate authorizations.

#### Request

```http
PUT /api/v1/roles/{id}
Authorization: Bearer <access token here>
{
  "name": "Role name",
  "description": "Role description",
  "permissions": [
    "permission id here"
  ]
}
```

#### Response

```http
{
  "id": "16a639cc-2240-4d2f-8def-bea0a729dd9e",
  "name": "Role name",
  "description": "Role description",
  "permissions": [
    {
      "id": "permission id here",
      "name": "CAN_UPDATE_SELF",
      "description": "The ability to update your own user",
      "createdAt": "2023-08-01T00:16:26.911565688+00:00",
      "updatedAt": "2023-08-01T00:16:26.911565688+00:00"
    }
  ],
  "createdAt": "2023-08-01T00:16:27.223266792+00:00",
  "updatedAt": "2023-08-01T00:16:27.223266792+00:00"
}
```

### Delete

`Role` entities can be deleted by users with the appropriate authorizations.

#### Request

```http
DELETE /api/v1/roles/{id}
AUthorization: Bearer <access token here>
```

#### Response

```http
200 OK
```

## Permissions

Permissions can be managed using the following CRUD endpoints:

-   `/api/v1/permissions/`
-   `/api/v1/permissions/{id}`

### Create

`Permission` entities can be created by users with the appropriate authorizations.

#### Request

```http
POST /api/v1/permissions/
Authorization: Bearer <access token here>
{
  "name": "CAN_UPDATE_SELF",
  "description": "The ability to update your own user"
}
```

#### Response

```http
{
  "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
  "name": "CAN_UPDATE_SELF",
  "description": "The ability to update your own user"
}
```

### Read

`Permission` entities can be read by users with the appropriate authorizations.

#### Find a single permission

Find a `Permission` entity by its ID.

##### Request

```http
GET /api/v1/permissions/{id}
Authorization: Bearer <access token here>
```

##### Response

```http
{
  "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
  "name": "CAN_UPDATE_SELF",
  "description": "The ability to update your own user"
}
```

#### Find all permissions

Find all `Permission` entities, within the given `page` and `limit` query parameters.

##### Request

```http
GET /api/v1/permissions/
Authorization: Bearer <access token here>
```

##### Response

```http
[
  {
    "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
    "name": "CAN_UPDATE_SELF",
    "description": "The ability to update your own user"
  },
  ...
]
```

#### Searching

Search for specific `Permission` entities with a given `text` query parameter.

##### Request

```http
GET /api/v1/permissions/?text=CAN_UPDATE_SELF
Authorization: Bearer <access token here>
```

##### Response

```http
[
  {
    "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
    "name": "CAN_UPDATE_SELF",
    "description": "The ability to update your own user"
  },
  ...
]
```

### Update

`Permission` entities can be updated by users with the appropriate authorizations.

#### Request

```http
PUT /api/v1/permissions/{id}
Authorization: Bearer <access token here>
{
  "name": "CAN_UPDATE_SELF",
  "description": "The ability to update your own user"
}
```

#### Response

```http
{
  "id": "078bb9bf-21c4-4a5f-8f30-f7367a1de1b9",
  "name": "CAN_UPDATE_SELF",
  "description": "The ability to update your own user"
}
```

### Delete

`Permission` entities can be deleted by users with the appropriate authorizations.

#### Request

```http
DELETE /api/v1/permissions/{id}
Authorization: Bearer <access token here>
```

#### Response

```http
200 OK
```

### Searching

Some endpoints, like the ones for retrieving all users, roles and permissions support text searching if automatic index
creation is enabled or a text index was created manually. You can search by providing a `text` query parameter. The
search will be performed on the following
fields:

**Users**

-   `id`
-   `username`
-   `email`
-   `firstName`
-   `lastName`

**Roles**

-   `id`
-   `name`

**Permissions**

-   `id`
-   `name`

### Pagination

Some endpoints, like the ones for retrieving all users, roles and permissions support pagination. You can provide a `limit`
and `page` query parameter to control the amount of entities that are returned and the page that should be returned.

If no `page` or `limit` query parameter is provided, `auth-rs` will resort to its default values. The default limit
is `100` and the default page is `1`.

#### Request

```http
GET /api/v1/users/?limit=10&page=2
Authorization: Bearer <access token here>
```

### Health

The health endpoint can be used to check if the service is up and running.
If no response is received, the service is considered to be down.

#### Request

```http
GET /health/
```

#### Response

```http
200 OK
{
  "status": "UP"
}
```

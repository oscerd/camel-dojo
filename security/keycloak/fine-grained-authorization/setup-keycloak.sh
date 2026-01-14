#!/bin/bash
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Setup script for Fine-Grained Authorization example
# This script creates a realm with document-based permissions

set -e

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM_NAME="documents"
CLIENT_ID="document-api"

echo "=============================================="
echo "Fine-Grained Authorization - Keycloak Setup"
echo "=============================================="
echo "Keycloak URL: $KEYCLOAK_URL"
echo "Realm: $REALM_NAME"
echo "=============================================="

# Function to get admin token
get_admin_token() {
    curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$ADMIN_USER" \
        -d "password=$ADMIN_PASSWORD" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" | jq -r '.access_token'
}

# Wait for Keycloak to be ready
echo "Waiting for Keycloak to be ready..."
until curl -s "$KEYCLOAK_URL/realms/master" > /dev/null 2>&1; do
    echo "  Keycloak not ready yet, waiting..."
    sleep 2
done
echo "Keycloak is ready!"

# Get admin token
echo "Getting admin token..."
TOKEN=$(get_admin_token)
if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to get admin token. Check credentials."
    exit 1
fi
echo "Admin token obtained."

# Create realm
echo "Creating realm '$REALM_NAME'..."
REALM_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME")

if [ "$REALM_EXISTS" == "200" ]; then
    echo "  Realm already exists, skipping creation."
else
    curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "realm": "'"$REALM_NAME"'",
            "enabled": true,
            "displayName": "Documents Realm",
            "registrationAllowed": false
        }'
    echo "  Realm created."
fi

# Refresh token
TOKEN=$(get_admin_token)

# Create roles
echo "Creating roles..."
ROLES=("employee" "manager" "admin" "confidential-access")
for ROLE in "${ROLES[@]}"; do
    ROLE_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")

    if [ "$ROLE_EXISTS" != "200" ]; then
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "name": "'"$ROLE"'",
                "description": "'"${ROLE^}"' role"
            }'
        echo "  Role '$ROLE' created."
    else
        echo "  Role '$ROLE' already exists."
    fi
done

# Create client (without authorization services for simplicity - RBAC based)
echo "Creating client '$CLIENT_ID'..."
CLIENT_EXISTS=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID" | jq -r '.[0].id // empty')

if [ -n "$CLIENT_EXISTS" ]; then
    echo "  Client already exists."
    CLIENT_UUID=$CLIENT_EXISTS
else
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "clientId": "'"$CLIENT_ID"'",
            "name": "Document API",
            "enabled": true,
            "clientAuthenticatorType": "client-secret",
            "secret": "document-api-secret-12345",
            "redirectUris": ["http://localhost:8080/*"],
            "publicClient": false,
            "protocol": "openid-connect",
            "directAccessGrantsEnabled": true,
            "serviceAccountsEnabled": true,
            "standardFlowEnabled": true
        }'
    echo "  Client created."

    CLIENT_UUID=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
fi

# Get client secret
CLIENT_SECRET=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" | jq -r '.value')
echo "  Client secret: $CLIENT_SECRET"

# Create users with different access levels
echo ""
echo "Creating users..."

# Regular employee - can read public documents
echo "  Creating 'employee-user'..."
USER_EXISTS=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=employee-user" | jq -r '.[0].id // empty')

if [ -z "$USER_EXISTS" ]; then
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "employee-user",
            "email": "employee@example.com",
            "firstName": "Regular",
            "lastName": "Employee",
            "enabled": true,
            "emailVerified": true,
            "credentials": [{
                "type": "password",
                "value": "password",
                "temporary": false
            }]
        }'

    USER_ID=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=employee-user" | jq -r '.[0].id')

    ROLE_DATA=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/employee")
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$USER_ID/role-mappings/realm" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "[$ROLE_DATA]" 2>/dev/null || true
    echo "    Created with 'employee' role."
else
    echo "    Already exists."
fi

# Manager - can read/write documents, access confidential
echo "  Creating 'manager-user'..."
USER_EXISTS=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=manager-user" | jq -r '.[0].id // empty')

if [ -z "$USER_EXISTS" ]; then
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "manager-user",
            "email": "manager@example.com",
            "firstName": "Department",
            "lastName": "Manager",
            "enabled": true,
            "emailVerified": true,
            "credentials": [{
                "type": "password",
                "value": "password",
                "temporary": false
            }]
        }'

    USER_ID=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=manager-user" | jq -r '.[0].id')

    for ROLE in "employee" "manager" "confidential-access"; do
        ROLE_DATA=$(curl -s \
            -H "Authorization: Bearer $TOKEN" \
            "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$USER_ID/role-mappings/realm" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "[$ROLE_DATA]" 2>/dev/null || true
    done
    echo "    Created with 'employee', 'manager', 'confidential-access' roles."
else
    echo "    Already exists."
fi

# Admin - full access
echo "  Creating 'admin-user'..."
USER_EXISTS=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=admin-user" | jq -r '.[0].id // empty')

if [ -z "$USER_EXISTS" ]; then
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "admin-user",
            "email": "admin@example.com",
            "firstName": "System",
            "lastName": "Administrator",
            "enabled": true,
            "emailVerified": true,
            "credentials": [{
                "type": "password",
                "value": "password",
                "temporary": false
            }]
        }'

    USER_ID=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=admin-user" | jq -r '.[0].id')

    for ROLE in "${ROLES[@]}"; do
        ROLE_DATA=$(curl -s \
            -H "Authorization: Bearer $TOKEN" \
            "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$USER_ID/role-mappings/realm" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "[$ROLE_DATA]" 2>/dev/null || true
    done
    echo "    Created with all roles."
else
    echo "    Already exists."
fi

# Update application.properties
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo ""
echo "Updating application.properties..."
sed -i "s|keycloak.client.secret=.*|keycloak.client.secret=$CLIENT_SECRET|g" "$SCRIPT_DIR/application.properties"

echo ""
echo "=============================================="
echo "Setup Complete!"
echo "=============================================="
echo ""
echo "Realm: $REALM_NAME"
echo "Client ID: $CLIENT_ID"
echo "Client Secret: $CLIENT_SECRET"
echo ""
echo "Roles created:"
echo "  - employee: Basic document read access"
echo "  - manager: Read/write access, confidential documents"
echo "  - admin: Full access to all documents and settings"
echo "  - confidential-access: Access to confidential documents"
echo ""
echo "Users created:"
echo "  - employee-user / password (role: employee)"
echo "    Can access: public documents only"
echo ""
echo "  - manager-user / password (roles: employee, manager, confidential-access)"
echo "    Can access: public + confidential documents, can edit"
echo ""
echo "  - admin-user / password (roles: all)"
echo "    Can access: all documents including restricted, admin settings"
echo ""
echo "To run the example:"
echo "  jbang -Dcamel.jbang.version=4.18.0-SNAPSHOT camel@apache/camel run --port 8081 fine-grained-authz.camel.yaml --properties application.properties --dep camel:keycloak"
echo ""
echo "To test with different users:"
echo ""
echo "  # As employee (limited access):"
echo "  export TOKEN=\$(curl -s -X POST '$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token' \\"
echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "    -d 'username=employee-user&password=password&grant_type=password&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET' \\"
echo "    | jq -r '.access_token')"
echo "  curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:8080/api/documents"
echo ""
echo "  # As manager (more access):"
echo "  export TOKEN=\$(curl -s -X POST '$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token' \\"
echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "    -d 'username=manager-user&password=password&grant_type=password&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET' \\"
echo "    | jq -r '.access_token')"
echo ""
echo "  # As admin (full access):"
echo "  export TOKEN=\$(curl -s -X POST '$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token' \\"
echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "    -d 'username=admin-user&password=password&grant_type=password&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET' \\"
echo "    | jq -r '.access_token')"
echo ""

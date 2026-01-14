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

# Setup script for Microservices API Gateway example
# This script configures Keycloak with the required realm, client, roles, and users

set -e

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM_NAME="microservices"
CLIENT_ID="api-gateway"

echo "=============================================="
echo "Microservices API Gateway - Keycloak Setup"
echo "=============================================="
echo "Keycloak URL: $KEYCLOAK_URL"
echo "Realm: $REALM_NAME"
echo "Client: $CLIENT_ID"
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
            "displayName": "Microservices",
            "registrationAllowed": false,
            "loginWithEmailAllowed": true,
            "duplicateEmailsAllowed": false,
            "resetPasswordAllowed": true,
            "editUsernameAllowed": false,
            "bruteForceProtected": true
        }'
    echo "  Realm created."
fi

# Refresh token after realm creation
TOKEN=$(get_admin_token)

# Create roles
echo "Creating roles..."
ROLES=("api-user" "api-admin" "orders-read" "orders-write" "users-read" "users-admin")
for ROLE in "${ROLES[@]}"; do
    ROLE_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")

    if [ "$ROLE_EXISTS" == "200" ]; then
        echo "  Role '$ROLE' already exists."
    else
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "name": "'"$ROLE"'",
                "description": "Role for '"$ROLE"'"
            }'
        echo "  Role '$ROLE' created."
    fi
done

# Create client
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
            "name": "API Gateway Client",
            "enabled": true,
            "clientAuthenticatorType": "client-secret",
            "secret": "api-gateway-secret",
            "redirectUris": ["http://localhost:8080/*"],
            "webOrigins": ["*"],
            "publicClient": false,
            "protocol": "openid-connect",
            "directAccessGrantsEnabled": true,
            "serviceAccountsEnabled": true,
            "authorizationServicesEnabled": false,
            "standardFlowEnabled": true
        }'
    echo "  Client created."

    # Get client UUID
    CLIENT_UUID=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
fi

# Get client secret
CLIENT_SECRET=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" | jq -r '.value')
echo "  Client secret: $CLIENT_SECRET"

# Create regular user
echo "Creating user 'user'..."
USER_EXISTS=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=user" | jq -r '.[0].id // empty')

if [ -n "$USER_EXISTS" ]; then
    echo "  User 'user' already exists."
    USER_ID=$USER_EXISTS
else
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "user",
            "email": "user@example.com",
            "firstName": "Regular",
            "lastName": "User",
            "enabled": true,
            "emailVerified": true,
            "credentials": [{
                "type": "password",
                "value": "password",
                "temporary": false
            }]
        }'
    echo "  User 'user' created."

    USER_ID=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=user" | jq -r '.[0].id')
fi

# Assign roles to regular user
echo "Assigning roles to 'user'..."
USER_ROLES=("api-user" "orders-read")
for ROLE in "${USER_ROLES[@]}"; do
    ROLE_DATA=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")

    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$USER_ID/role-mappings/realm" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "[$ROLE_DATA]" 2>/dev/null || true
    echo "  Assigned '$ROLE' to user."
done

# Create admin user
echo "Creating user 'admin-user'..."
ADMIN_USER_EXISTS=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=admin-user" | jq -r '.[0].id // empty')

if [ -n "$ADMIN_USER_EXISTS" ]; then
    echo "  User 'admin-user' already exists."
    ADMIN_USER_ID=$ADMIN_USER_EXISTS
else
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "admin-user",
            "email": "admin@example.com",
            "firstName": "Admin",
            "lastName": "User",
            "enabled": true,
            "emailVerified": true,
            "credentials": [{
                "type": "password",
                "value": "password",
                "temporary": false
            }]
        }'
    echo "  User 'admin-user' created."

    ADMIN_USER_ID=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=admin-user" | jq -r '.[0].id')
fi

# Assign all roles to admin user
echo "Assigning roles to 'admin-user'..."
for ROLE in "${ROLES[@]}"; do
    ROLE_DATA=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")

    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$ADMIN_USER_ID/role-mappings/realm" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "[$ROLE_DATA]" 2>/dev/null || true
    echo "  Assigned '$ROLE' to admin-user."
done

# Update application.properties with the client secret
echo ""
echo "Updating application.properties with client secret..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
echo "Users created:"
echo "  - user / password (roles: api-user, orders-read)"
echo "  - admin-user / password (roles: all)"
echo ""
echo "Keycloak Admin Console: $KEYCLOAK_URL/admin"
echo ""
echo "To run the example:"
echo "  jbang -Dcamel.jbang.version=4.18.0-SNAPSHOT camel@apache/camel run --port 8081 api-gateway.camel.yaml --properties application.properties --dep camel:keycloak"
echo ""
echo "To get a token for testing:"
echo "  export TOKEN=\$(curl -s -X POST '$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token' \\"
echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "    -d 'username=user&password=password&grant_type=password&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET' \\"
echo "    | jq -r '.access_token')"
echo ""

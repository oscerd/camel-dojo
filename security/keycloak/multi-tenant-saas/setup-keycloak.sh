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

# Setup script for Multi-Tenant SaaS example
# This script creates tenant realms with their own clients and users

set -e

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
CLIENT_ID="saas-app"
TENANTS=("acme" "globex" "initech")

echo "=============================================="
echo "Multi-Tenant SaaS - Keycloak Setup"
echo "=============================================="
echo "Keycloak URL: $KEYCLOAK_URL"
echo "Tenants: ${TENANTS[*]}"
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

# Store client secrets
declare -A CLIENT_SECRETS

# Create each tenant realm
for TENANT in "${TENANTS[@]}"; do
    echo ""
    echo "Setting up tenant: $TENANT"
    echo "-------------------------------------------"

    # Create realm
    echo "  Creating realm '$TENANT'..."
    REALM_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$TENANT")

    if [ "$REALM_EXISTS" == "200" ]; then
        echo "    Realm already exists, skipping creation."
    else
        curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "realm": "'"$TENANT"'",
                "enabled": true,
                "displayName": "'"${TENANT^} Corporation"'",
                "registrationAllowed": false,
                "loginWithEmailAllowed": true,
                "duplicateEmailsAllowed": false,
                "resetPasswordAllowed": true
            }'
        echo "    Realm created."
    fi

    # Refresh token
    TOKEN=$(get_admin_token)

    # Create roles
    echo "  Creating roles..."
    ROLES=("tenant-user" "tenant-admin")
    for ROLE in "${ROLES[@]}"; do
        ROLE_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $TOKEN" \
            "$KEYCLOAK_URL/admin/realms/$TENANT/roles/$ROLE")

        if [ "$ROLE_EXISTS" != "200" ]; then
            curl -s -X POST "$KEYCLOAK_URL/admin/realms/$TENANT/roles" \
                -H "Authorization: Bearer $TOKEN" \
                -H "Content-Type: application/json" \
                -d '{
                    "name": "'"$ROLE"'",
                    "description": "'"$ROLE"' role for '"$TENANT"'"
                }'
            echo "    Role '$ROLE' created."
        else
            echo "    Role '$ROLE' already exists."
        fi
    done

    # Create client
    echo "  Creating client '$CLIENT_ID'..."
    CLIENT_EXISTS=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$TENANT/clients?clientId=$CLIENT_ID" | jq -r '.[0].id // empty')

    if [ -n "$CLIENT_EXISTS" ]; then
        echo "    Client already exists."
        CLIENT_UUID=$CLIENT_EXISTS
    else
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$TENANT/clients" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "clientId": "'"$CLIENT_ID"'",
                "name": "SaaS Application",
                "enabled": true,
                "clientAuthenticatorType": "client-secret",
                "secret": "'"$TENANT"'-secret-12345",
                "redirectUris": ["http://localhost:8080/*"],
                "webOrigins": ["*"],
                "publicClient": false,
                "protocol": "openid-connect",
                "directAccessGrantsEnabled": true,
                "serviceAccountsEnabled": true,
                "standardFlowEnabled": true
            }'
        echo "    Client created."

        CLIENT_UUID=$(curl -s \
            -H "Authorization: Bearer $TOKEN" \
            "$KEYCLOAK_URL/admin/realms/$TENANT/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
    fi

    # Get client secret
    CLIENT_SECRET=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$TENANT/clients/$CLIENT_UUID/client-secret" | jq -r '.value')
    CLIENT_SECRETS[$TENANT]=$CLIENT_SECRET
    echo "    Client secret: $CLIENT_SECRET"

    # Create regular user
    echo "  Creating user 'user@$TENANT.com'..."
    USER_EXISTS=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$TENANT/users?username=user@$TENANT.com" | jq -r '.[0].id // empty')

    if [ -z "$USER_EXISTS" ]; then
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$TENANT/users" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "username": "user@'"$TENANT"'.com",
                "email": "user@'"$TENANT"'.com",
                "firstName": "'"${TENANT^}"'",
                "lastName": "User",
                "enabled": true,
                "emailVerified": true,
                "credentials": [{
                    "type": "password",
                    "value": "password",
                    "temporary": false
                }]
            }'
        echo "    User created."

        USER_ID=$(curl -s \
            -H "Authorization: Bearer $TOKEN" \
            "$KEYCLOAK_URL/admin/realms/$TENANT/users?username=user@$TENANT.com" | jq -r '.[0].id')

        # Assign tenant-user role
        ROLE_DATA=$(curl -s \
            -H "Authorization: Bearer $TOKEN" \
            "$KEYCLOAK_URL/admin/realms/$TENANT/roles/tenant-user")
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$TENANT/users/$USER_ID/role-mappings/realm" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "[$ROLE_DATA]" 2>/dev/null || true
        echo "    Assigned 'tenant-user' role."
    else
        echo "    User already exists."
    fi

    # Create admin user
    echo "  Creating user 'admin@$TENANT.com'..."
    ADMIN_EXISTS=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$TENANT/users?username=admin@$TENANT.com" | jq -r '.[0].id // empty')

    if [ -z "$ADMIN_EXISTS" ]; then
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$TENANT/users" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "username": "admin@'"$TENANT"'.com",
                "email": "admin@'"$TENANT"'.com",
                "firstName": "'"${TENANT^}"'",
                "lastName": "Admin",
                "enabled": true,
                "emailVerified": true,
                "credentials": [{
                    "type": "password",
                    "value": "password",
                    "temporary": false
                }]
            }'
        echo "    Admin user created."

        ADMIN_ID=$(curl -s \
            -H "Authorization: Bearer $TOKEN" \
            "$KEYCLOAK_URL/admin/realms/$TENANT/users?username=admin@$TENANT.com" | jq -r '.[0].id')

        # Assign both roles
        for ROLE in "tenant-user" "tenant-admin"; do
            ROLE_DATA=$(curl -s \
                -H "Authorization: Bearer $TOKEN" \
                "$KEYCLOAK_URL/admin/realms/$TENANT/roles/$ROLE")
            curl -s -X POST "$KEYCLOAK_URL/admin/realms/$TENANT/users/$ADMIN_ID/role-mappings/realm" \
                -H "Authorization: Bearer $TOKEN" \
                -H "Content-Type: application/json" \
                -d "[$ROLE_DATA]" 2>/dev/null || true
        done
        echo "    Assigned roles to admin."
    else
        echo "    Admin user already exists."
    fi
done

# Update application.properties
echo ""
echo "Updating application.properties with client secrets..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for TENANT in "${TENANTS[@]}"; do
    sed -i "s|keycloak.$TENANT.client.secret=.*|keycloak.$TENANT.client.secret=${CLIENT_SECRETS[$TENANT]}|g" "$SCRIPT_DIR/application.properties"
done

echo ""
echo "=============================================="
echo "Setup Complete!"
echo "=============================================="
echo ""
echo "Tenants created:"
for TENANT in "${TENANTS[@]}"; do
    echo ""
    echo "  $TENANT:"
    echo "    Realm: $TENANT"
    echo "    Client: $CLIENT_ID"
    echo "    Client Secret: ${CLIENT_SECRETS[$TENANT]}"
    echo "    Users:"
    echo "      - user@$TENANT.com / password (role: tenant-user)"
    echo "      - admin@$TENANT.com / password (roles: tenant-user, tenant-admin)"
done
echo ""
echo "To run the example:"
echo "  jbang -Dcamel.jbang.version=4.18.0-SNAPSHOT camel@apache/camel run --port 8081 multi-tenant.camel.yaml --properties application.properties --dep camel:keycloak"
echo ""
echo "To get a token for a tenant:"
echo "  export TENANT=acme"
echo "  export TOKEN=\$(curl -s -X POST '$KEYCLOAK_URL/realms/\$TENANT/protocol/openid-connect/token' \\"
echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "    -d 'username=user@\$TENANT.com&password=password&grant_type=password&client_id=$CLIENT_ID&client_secret=\$TENANT-secret-12345' \\"
echo "    | jq -r '.access_token')"
echo ""

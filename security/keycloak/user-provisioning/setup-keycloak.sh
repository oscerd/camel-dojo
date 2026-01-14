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

# Setup script for User Provisioning example
# This script creates the enterprise realm with department roles

set -e

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM_NAME="enterprise"
CLIENT_ID="user-provisioning"

echo "=============================================="
echo "User Provisioning - Keycloak Setup"
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
            "displayName": "Enterprise",
            "registrationAllowed": false,
            "loginWithEmailAllowed": true,
            "duplicateEmailsAllowed": false,
            "resetPasswordAllowed": true,
            "verifyEmail": true,
            "loginTheme": "keycloak",
            "accountTheme": "keycloak.v2",
            "emailTheme": "keycloak"
        }'
    echo "  Realm created."
fi

# Refresh token
TOKEN=$(get_admin_token)

# Create department roles
echo "Creating department roles..."
DEPT_ROLES=("engineering" "sales" "marketing" "hr" "finance")
for ROLE in "${DEPT_ROLES[@]}"; do
    ROLE_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")

    if [ "$ROLE_EXISTS" != "200" ]; then
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "name": "'"$ROLE"'",
                "description": "'"${ROLE^}"' department role"
            }'
        echo "  Role '$ROLE' created."
    else
        echo "  Role '$ROLE' already exists."
    fi
done

# Create access-level roles
echo "Creating access-level roles..."
ACCESS_ROLES=("employee" "manager" "director" "admin")
for ROLE in "${ACCESS_ROLES[@]}"; do
    ROLE_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")

    if [ "$ROLE_EXISTS" != "200" ]; then
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "name": "'"$ROLE"'",
                "description": "'"${ROLE^}"' access level"
            }'
        echo "  Role '$ROLE' created."
    else
        echo "  Role '$ROLE' already exists."
    fi
done

# Create client with realm-admin privileges
echo "Creating client '$CLIENT_ID' with realm management permissions..."
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
            "name": "User Provisioning Service",
            "enabled": true,
            "clientAuthenticatorType": "client-secret",
            "secret": "provisioning-secret-12345",
            "redirectUris": ["http://localhost:8080/*"],
            "publicClient": false,
            "protocol": "openid-connect",
            "directAccessGrantsEnabled": true,
            "serviceAccountsEnabled": true,
            "standardFlowEnabled": false
        }'
    echo "  Client created."

    CLIENT_UUID=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
fi

# Get realm-management client ID
REALM_MGMT_CLIENT=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=realm-management" | jq -r '.[0].id')

# Get service account user
SERVICE_ACCOUNT_USER=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/service-account-user" | jq -r '.id')

if [ -n "$SERVICE_ACCOUNT_USER" ] && [ "$SERVICE_ACCOUNT_USER" != "null" ]; then
    echo "  Assigning realm-admin role to service account..."

    # Get realm-admin role from realm-management client
    REALM_ADMIN_ROLE=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$REALM_MGMT_CLIENT/roles/realm-admin")

    if [ -n "$REALM_ADMIN_ROLE" ] && [ "$REALM_ADMIN_ROLE" != "null" ]; then
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$SERVICE_ACCOUNT_USER/role-mappings/clients/$REALM_MGMT_CLIENT" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "[$REALM_ADMIN_ROLE]" 2>/dev/null || true
        echo "  Service account configured with realm-admin role."
    fi
fi

# Get client secret
CLIENT_SECRET=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" | jq -r '.value')
echo "  Client secret: $CLIENT_SECRET"

# Create sample CSV directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$SCRIPT_DIR/inbox" "$SCRIPT_DIR/processed" "$SCRIPT_DIR/error"
echo "Created CSV import directories."

# Create sample CSV file
cat > "$SCRIPT_DIR/inbox/sample-users.csv.example" << 'EOF'
username,email,firstName,lastName,department,jobTitle,manager
john.doe,john.doe@company.com,John,Doe,engineering,Software Engineer,jane.smith
jane.smith,jane.smith@company.com,Jane,Smith,engineering,Engineering Manager,
bob.wilson,bob.wilson@company.com,Bob,Wilson,sales,Account Executive,alice.jones
alice.jones,alice.jones@company.com,Alice,Jones,sales,Sales Director,
carol.white,carol.white@company.com,Carol,White,hr,HR Specialist,david.brown
david.brown,david.brown@company.com,David,Brown,hr,HR Manager,
EOF
echo "Created sample CSV file (rename to .csv to use)."

# Update application.properties
echo ""
echo "Updating application.properties..."
sed -i "s|keycloak.client.id=.*|keycloak.client.id=$CLIENT_ID|g" "$SCRIPT_DIR/application.properties"

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
echo "  Department: ${DEPT_ROLES[*]}"
echo "  Access Level: ${ACCESS_ROLES[*]}"
echo ""
echo "Directories:"
echo "  - inbox/: Place CSV files here for import"
echo "  - processed/: Successfully imported files"
echo "  - error/: Failed imports"
echo ""
echo "To run the example:"
echo "  jbang -Dcamel.jbang.version=4.18.0-SNAPSHOT camel@apache/camel run --port 8081 user-provisioning.camel.yaml --properties application.properties --dep camel:keycloak"
echo ""
echo "To create a user via API:"
echo "  curl -X POST http://localhost:8080/api/users \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"username\": \"newuser\", \"email\": \"new@company.com\", \"firstName\": \"New\", \"lastName\": \"User\", \"department\": \"engineering\"}'"
echo ""

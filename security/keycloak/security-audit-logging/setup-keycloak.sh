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

# Setup script for Security Audit Logging example
# This script enables event logging and creates an audit service client

set -e

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM_NAME="master"
CLIENT_ID="audit-service"

echo "=============================================="
echo "Security Audit Logging - Keycloak Setup"
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

# Enable events in the realm
echo "Enabling events logging..."
curl -s -X PUT "$KEYCLOAK_URL/admin/realms/$REALM_NAME" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "eventsEnabled": true,
        "eventsExpiration": 604800,
        "eventsListeners": ["jboss-logging"],
        "enabledEventTypes": [
            "LOGIN", "LOGIN_ERROR", "LOGOUT", "LOGOUT_ERROR",
            "REGISTER", "REGISTER_ERROR",
            "CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR",
            "CLIENT_LOGIN", "CLIENT_LOGIN_ERROR",
            "REFRESH_TOKEN", "REFRESH_TOKEN_ERROR",
            "VALIDATE_ACCESS_TOKEN", "VALIDATE_ACCESS_TOKEN_ERROR",
            "INTROSPECT_TOKEN", "INTROSPECT_TOKEN_ERROR",
            "FEDERATED_IDENTITY_LINK", "FEDERATED_IDENTITY_LINK_ERROR",
            "REMOVE_FEDERATED_IDENTITY", "REMOVE_FEDERATED_IDENTITY_ERROR",
            "UPDATE_EMAIL", "UPDATE_EMAIL_ERROR",
            "UPDATE_PROFILE", "UPDATE_PROFILE_ERROR",
            "UPDATE_PASSWORD", "UPDATE_PASSWORD_ERROR",
            "UPDATE_TOTP", "UPDATE_TOTP_ERROR",
            "VERIFY_EMAIL", "VERIFY_EMAIL_ERROR",
            "VERIFY_PROFILE", "VERIFY_PROFILE_ERROR",
            "REMOVE_TOTP", "REMOVE_TOTP_ERROR",
            "GRANT_CONSENT", "GRANT_CONSENT_ERROR",
            "UPDATE_CONSENT", "UPDATE_CONSENT_ERROR",
            "REVOKE_GRANT", "REVOKE_GRANT_ERROR",
            "SEND_VERIFY_EMAIL", "SEND_VERIFY_EMAIL_ERROR",
            "SEND_RESET_PASSWORD", "SEND_RESET_PASSWORD_ERROR",
            "SEND_IDENTITY_PROVIDER_LINK", "SEND_IDENTITY_PROVIDER_LINK_ERROR",
            "RESET_PASSWORD", "RESET_PASSWORD_ERROR",
            "RESTART_AUTHENTICATION", "RESTART_AUTHENTICATION_ERROR",
            "IDENTITY_PROVIDER_LINK_ACCOUNT", "IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR",
            "IDENTITY_PROVIDER_FIRST_LOGIN", "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR",
            "IDENTITY_PROVIDER_POST_LOGIN", "IDENTITY_PROVIDER_POST_LOGIN_ERROR",
            "IMPERSONATE", "IMPERSONATE_ERROR",
            "CUSTOM_REQUIRED_ACTION", "CUSTOM_REQUIRED_ACTION_ERROR",
            "EXECUTE_ACTIONS", "EXECUTE_ACTIONS_ERROR",
            "EXECUTE_ACTION_TOKEN", "EXECUTE_ACTION_TOKEN_ERROR",
            "CLIENT_REGISTER", "CLIENT_REGISTER_ERROR",
            "CLIENT_UPDATE", "CLIENT_UPDATE_ERROR",
            "CLIENT_DELETE", "CLIENT_DELETE_ERROR",
            "CLIENT_INITIATED_ACCOUNT_LINKING", "CLIENT_INITIATED_ACCOUNT_LINKING_ERROR",
            "TOKEN_EXCHANGE", "TOKEN_EXCHANGE_ERROR",
            "OAUTH2_DEVICE_AUTH", "OAUTH2_DEVICE_AUTH_ERROR",
            "OAUTH2_DEVICE_VERIFY_USER_CODE", "OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR",
            "OAUTH2_DEVICE_CODE_TO_TOKEN", "OAUTH2_DEVICE_CODE_TO_TOKEN_ERROR",
            "AUTHREQID_TO_TOKEN", "AUTHREQID_TO_TOKEN_ERROR",
            "PERMISSION_TOKEN", "PERMISSION_TOKEN_ERROR",
            "DELETE_ACCOUNT", "DELETE_ACCOUNT_ERROR",
            "PUSHED_AUTHORIZATION_REQUEST", "PUSHED_AUTHORIZATION_REQUEST_ERROR"
        ],
        "adminEventsEnabled": true,
        "adminEventsDetailsEnabled": true
    }'
echo "  Events logging enabled."

# Refresh token
TOKEN=$(get_admin_token)

# Create audit service client
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
            "name": "Audit Service",
            "enabled": true,
            "clientAuthenticatorType": "client-secret",
            "secret": "audit-secret-12345",
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
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=master-realm" | jq -r '.[0].id')

# Get service account user
SERVICE_ACCOUNT_USER=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/service-account-user" | jq -r '.id')

if [ -n "$SERVICE_ACCOUNT_USER" ] && [ "$SERVICE_ACCOUNT_USER" != "null" ]; then
    echo "  Assigning view-events role to service account..."

    # Get view-events role
    VIEW_EVENTS_ROLE=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$REALM_MGMT_CLIENT/roles/view-events")

    if [ -n "$VIEW_EVENTS_ROLE" ] && [ "$VIEW_EVENTS_ROLE" != "null" ]; then
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$SERVICE_ACCOUNT_USER/role-mappings/clients/$REALM_MGMT_CLIENT" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "[$VIEW_EVENTS_ROLE]" 2>/dev/null || true
        echo "  Service account configured with view-events role."
    fi

    # Also assign view-users for user info enrichment
    VIEW_USERS_ROLE=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$REALM_MGMT_CLIENT/roles/view-users")

    if [ -n "$VIEW_USERS_ROLE" ] && [ "$VIEW_USERS_ROLE" != "null" ]; then
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$SERVICE_ACCOUNT_USER/role-mappings/clients/$REALM_MGMT_CLIENT" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "[$VIEW_USERS_ROLE]" 2>/dev/null || true
        echo "  Service account configured with view-users role."
    fi
fi

# Get client secret
CLIENT_SECRET=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" | jq -r '.value')
echo "  Client secret: $CLIENT_SECRET"

# Create test user for generating events
echo "Creating test user 'testuser'..."
USER_EXISTS=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=testuser" | jq -r '.[0].id // empty')

if [ -z "$USER_EXISTS" ]; then
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "testuser",
            "email": "testuser@example.com",
            "firstName": "Test",
            "lastName": "User",
            "enabled": true,
            "emailVerified": true,
            "credentials": [{
                "type": "password",
                "value": "password",
                "temporary": false
            }]
        }'
    echo "  Test user created."
else
    echo "  Test user already exists."
fi

# Create directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$SCRIPT_DIR/audit-logs" "$SCRIPT_DIR/reports"
echo "Created audit log directories."

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
echo "Events enabled:"
echo "  - User events: LOGIN, LOGOUT, REGISTER, UPDATE_PASSWORD, etc."
echo "  - Admin events: CREATE, UPDATE, DELETE with representations"
echo ""
echo "Test user: testuser / password"
echo ""
echo "Directories:"
echo "  - audit-logs/: Stored audit events"
echo "  - reports/: Compliance reports"
echo ""
echo "To run the example:"
echo "  jbang -Dcamel.jbang.version=4.18.0-SNAPSHOT camel@apache/camel run --port 8081 security-audit.camel.yaml --properties application.properties --dep camel:keycloak"
echo ""
echo "To generate test events, login with the test user:"
echo "  curl -X POST '$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token' \\"
echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "    -d 'username=testuser&password=password&grant_type=password&client_id=admin-cli'"
echo ""

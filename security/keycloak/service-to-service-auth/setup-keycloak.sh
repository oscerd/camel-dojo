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

# Setup script for Service-to-Service Authentication example
# This script creates service clients for M2M authentication

set -e

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM_NAME="services"

# Service definitions
declare -A SERVICES
SERVICES["order-service"]="orders:read,orders:write,orders:process"
SERVICES["inventory-service"]="inventory:read,inventory:write,inventory:admin"
SERVICES["notification-service"]="notifications:send"

echo "=============================================="
echo "Service-to-Service Auth - Keycloak Setup"
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
            "displayName": "Services Realm",
            "registrationAllowed": false
        }'
    echo "  Realm created."
fi

# Refresh token
TOKEN=$(get_admin_token)

# Create all service roles first
echo "Creating service roles..."
ALL_ROLES=()
for SERVICE in "${!SERVICES[@]}"; do
    IFS=',' read -ra ROLES <<< "${SERVICES[$SERVICE]}"
    for ROLE in "${ROLES[@]}"; do
        ALL_ROLES+=("$ROLE")
    done
done

for ROLE in "${ALL_ROLES[@]}"; do
    ROLE_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")

    if [ "$ROLE_EXISTS" != "200" ]; then
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "name": "'"$ROLE"'",
                "description": "Service role: '"$ROLE"'"
            }'
        echo "  Role '$ROLE' created."
    else
        echo "  Role '$ROLE' already exists."
    fi
done

# Store client secrets
declare -A CLIENT_SECRETS

# Create service clients
for SERVICE in "${!SERVICES[@]}"; do
    echo ""
    echo "Setting up service: $SERVICE"
    echo "-------------------------------------------"

    # Create client
    CLIENT_EXISTS=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=$SERVICE" | jq -r '.[0].id // empty')

    if [ -n "$CLIENT_EXISTS" ]; then
        echo "  Client already exists."
        CLIENT_UUID=$CLIENT_EXISTS
    else
        curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "clientId": "'"$SERVICE"'",
                "name": "'"${SERVICE//-/ }"'",
                "enabled": true,
                "clientAuthenticatorType": "client-secret",
                "secret": "'"$SERVICE"'-secret-12345",
                "publicClient": false,
                "protocol": "openid-connect",
                "directAccessGrantsEnabled": false,
                "serviceAccountsEnabled": true,
                "standardFlowEnabled": false,
                "attributes": {
                    "access.token.lifespan": "300"
                }
            }'
        echo "  Client created."

        CLIENT_UUID=$(curl -s \
            -H "Authorization: Bearer $TOKEN" \
            "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=$SERVICE" | jq -r '.[0].id')
    fi

    # Get client secret
    CLIENT_SECRET=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" | jq -r '.value')
    CLIENT_SECRETS[$SERVICE]=$CLIENT_SECRET
    echo "  Client secret: $CLIENT_SECRET"

    # Get service account user
    SERVICE_ACCOUNT_USER=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/service-account-user" | jq -r '.id')

    if [ -n "$SERVICE_ACCOUNT_USER" ] && [ "$SERVICE_ACCOUNT_USER" != "null" ]; then
        # Assign service's own roles
        echo "  Assigning roles to service account..."
        IFS=',' read -ra ROLES <<< "${SERVICES[$SERVICE]}"
        for ROLE in "${ROLES[@]}"; do
            ROLE_DATA=$(curl -s \
                -H "Authorization: Bearer $TOKEN" \
                "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/$ROLE")

            curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$SERVICE_ACCOUNT_USER/role-mappings/realm" \
                -H "Authorization: Bearer $TOKEN" \
                -H "Content-Type: application/json" \
                -d "[$ROLE_DATA]" 2>/dev/null || true
            echo "    Assigned '$ROLE'."
        done
    fi
done

# Cross-service permissions
echo ""
echo "Configuring cross-service permissions..."

# Order service needs inventory:read to check stock
ORDER_SA=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=order-service" | jq -r '.[0].id')
ORDER_SA_USER=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$ORDER_SA/service-account-user" | jq -r '.id')

if [ -n "$ORDER_SA_USER" ] && [ "$ORDER_SA_USER" != "null" ]; then
    INVENTORY_READ=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/inventory:read")
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$ORDER_SA_USER/role-mappings/realm" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "[$INVENTORY_READ]" 2>/dev/null || true
    echo "  order-service granted inventory:read"

    NOTIF_SEND=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/notifications:send")
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$ORDER_SA_USER/role-mappings/realm" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "[$NOTIF_SEND]" 2>/dev/null || true
    echo "  order-service granted notifications:send"
fi

# Notification service needs orders:read
NOTIF_SA=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=notification-service" | jq -r '.[0].id')
NOTIF_SA_USER=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$NOTIF_SA/service-account-user" | jq -r '.id')

if [ -n "$NOTIF_SA_USER" ] && [ "$NOTIF_SA_USER" != "null" ]; then
    ORDERS_READ=$(curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles/orders:read")
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$NOTIF_SA_USER/role-mappings/realm" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "[$ORDERS_READ]" 2>/dev/null || true
    echo "  notification-service granted orders:read"
fi

# Update application.properties
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo ""
echo "Updating application.properties..."
sed -i "s|service.client.secret=.*|service.client.secret=${CLIENT_SECRETS["order-service"]}|g" "$SCRIPT_DIR/application.properties"
sed -i "s|keycloak.client.secret=.*|keycloak.client.secret=${CLIENT_SECRETS["order-service"]}|g" "$SCRIPT_DIR/application.properties"

echo ""
echo "=============================================="
echo "Setup Complete!"
echo "=============================================="
echo ""
echo "Realm: $REALM_NAME"
echo ""
echo "Services created:"
for SERVICE in "${!SERVICES[@]}"; do
    echo ""
    echo "  $SERVICE:"
    echo "    Client Secret: ${CLIENT_SECRETS[$SERVICE]}"
    echo "    Own Roles: ${SERVICES[$SERVICE]}"
done
echo ""
echo "Cross-service permissions:"
echo "  - order-service can call inventory-service (inventory:read)"
echo "  - order-service can call notification-service (notifications:send)"
echo "  - notification-service can call order-service (orders:read)"
echo ""
echo "To run the example:"
echo "  jbang -Dcamel.jbang.version=4.18.0-SNAPSHOT camel@apache/camel run --port 8081 m2m-service.camel.yaml --properties application.properties --dep camel:keycloak"
echo ""
echo "To get a service token:"
echo "  export TOKEN=\$(curl -s -X POST '$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token' \\"
echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "    -d 'grant_type=client_credentials&client_id=order-service&client_secret=order-service-secret-12345' \\"
echo "    | jq -r '.access_token')"
echo ""

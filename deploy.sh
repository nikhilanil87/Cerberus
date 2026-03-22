#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Deploy to Google Cloud Run via Cloud Build
# Run this from VS Code terminal after: gcloud auth login
# ─────────────────────────────────────────────────────────────
set -e

PROJECT_ID=${GCP_PROJECT_ID:-$(gcloud config get-value project)}
REGION="us-central1"
SERVICE_NAME="remediation-agent"
IMAGE="gcr.io/$PROJECT_ID/$SERVICE_NAME"
SA_NAME="remediation-agent-sa"
SA_EMAIL="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

echo "🔧 Project: $PROJECT_ID"

# ── 1. Enable required APIs (safe to re-run) ──
echo "🔌 Enabling GCP APIs..."
gcloud services enable \
  run.googleapis.com \
  aiplatform.googleapis.com \
  secretmanager.googleapis.com \
  containerregistry.googleapis.com \
  cloudbuild.googleapis.com \
  --project $PROJECT_ID

# ── 2. Create service account (if not exists) ──
echo "👤 Setting up service account..."
gcloud iam service-accounts create $SA_NAME \
  --display-name="Remediation Agent SA" \
  --project $PROJECT_ID 2>/dev/null || echo "SA already exists"

# Grant Vertex AI access (no API key needed — IAM handles it)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/aiplatform.user" --quiet

# Grant Secret Manager access
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/secretmanager.secretAccessor" --quiet

# ── 3. Store secrets in Secret Manager ──
echo "🔒 Storing secrets..."
echo -n "$AUTH0_CLIENT_SECRET" | gcloud secrets create auth0-client-secret \
  --data-file=- --project $PROJECT_ID 2>/dev/null || \
  echo -n "$AUTH0_CLIENT_SECRET" | gcloud secrets versions add auth0-client-secret \
  --data-file=- --project $PROJECT_ID

echo -n "$MGMT_CLIENT_SECRET" | gcloud secrets create mgmt-client-secret \
  --data-file=- --project $PROJECT_ID 2>/dev/null || \
  echo -n "$MGMT_CLIENT_SECRET" | gcloud secrets versions add mgmt-client-secret \
  --data-file=- --project $PROJECT_ID

echo -n "$APP_SECRET_KEY" | gcloud secrets create app-secret-key \
  --data-file=- --project $PROJECT_ID 2>/dev/null || \
  echo -n "$APP_SECRET_KEY" | gcloud secrets versions add app-secret-key \
  --data-file=- --project $PROJECT_ID

# ── 4. Build image via Cloud Build (no Docker needed locally) ──
echo "🏗️  Building image via Cloud Build..."
gcloud builds submit \
  --tag $IMAGE \
  --project $PROJECT_ID

# ── 5. Deploy to Cloud Run ──
echo "🚀 Deploying to Cloud Run..."
gcloud run deploy $SERVICE_NAME \
  --image $IMAGE \
  --platform managed \
  --region $REGION \
  --service-account $SA_EMAIL \
  --allow-unauthenticated \
  --set-env-vars "GCP_PROJECT_ID=$PROJECT_ID" \
  --set-env-vars "GCP_LOCATION=$REGION" \
  --set-env-vars "GEMINI_MODEL=gemini-2.5-flash" \
  --set-env-vars "AUTH0_DOMAIN=$AUTH0_DOMAIN" \
  --set-env-vars "AUTH0_AUDIENCE=$AUTH0_AUDIENCE" \
  --set-env-vars "AUTH0_ROLES_NAMESPACE=$AUTH0_ROLES_NAMESPACE" \
  --set-secrets "AUTH0_CLIENT_SECRET=auth0-client-secret:latest" \
  --set-secrets "MGMT_CLIENT_SECRET=mgmt-client-secret:latest" \
  --set-secrets "APP_SECRET_KEY=app-secret-key:latest" \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 10 \
  --port 8000 \
  --project $PROJECT_ID

echo ""
echo "✅ Deployed!"
gcloud run services describe $SERVICE_NAME \
  --platform managed --region $REGION \
  --format "value(status.url)" --project $PROJECT_ID
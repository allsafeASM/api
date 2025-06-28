# Discord Webhook Setup Guide

This guide explains how to set up Discord webhook notifications for the AllSafe ASM Worker.

## Step 1: Create a Discord Webhook

1. **Open Discord** and navigate to your server
2. **Go to Server Settings** → **Integrations** → **Webhooks**
3. **Click "New Webhook"**
4. **Configure the webhook:**
   - **Name**: `AllSafe ASM Bot`
   - **Channel**: Select the channel where you want notifications
   - **Avatar**: Upload a custom avatar (optional)
5. **Copy the Webhook URL** (you'll need this for configuration)

## Step 2: Configure Environment Variables

Add the following environment variables to your deployment:

```bash
# Enable Discord notifications
ENABLE_DISCORD_NOTIFICATIONS=true

# Your Discord webhook URL (replace with your actual URL)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN

# Optional: Webhook timeout (default: 30 seconds)
DISCORD_WEBHOOK_TIMEOUT=30
```

## Step 3: Test the Configuration

1. **Start the worker** with Discord notifications enabled
2. **Send a test task** to the queue
3. **Check Discord** for notifications

You should see notifications for:
- 🔄 Task Received
- ⚡ Task Started  
- ✅ Task Completed
- 💾 Result Stored
- 📢 Notification Sent

## Step 4: Customize Notifications (Optional)

### Modify Bot Username and Avatar

Edit `internal/notification/discord.go`:

```go
return DiscordWebhookPayload{
    Username:  "Your Custom Bot Name",  // Change this
    AvatarURL: "https://your-avatar-url.com/image.png",  // Change this
    Embeds:    []DiscordEmbed{embed},
}
```

### Customize Colors

Modify the color constants in `internal/notification/discord.go`:

```go
const (
    ColorInfo    = 0x3498db // Blue
    ColorSuccess = 0x2ecc71 // Green
    ColorWarning = 0xf39c12 // Orange
    ColorError   = 0xe74c3c // Red
    ColorPurple  = 0x9b59b6 // Purple
)
```

## Step 5: Security Considerations

1. **Keep webhook URLs secret** - Don't commit them to version control
2. **Use environment variables** - Store webhook URLs in secure environment variables
3. **Monitor webhook usage** - Check Discord server audit logs for webhook activity
4. **Rotate webhook tokens** - Regularly regenerate webhook tokens for security

## Troubleshooting

### No Notifications Appearing

1. **Check webhook URL** - Ensure the URL is correct and not expired
2. **Verify permissions** - Make sure the webhook has permission to post in the channel
3. **Check logs** - Look for webhook error messages in the application logs
4. **Test webhook manually** - Use curl or Postman to test the webhook URL directly

### Example Manual Test

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"Test Bot","content":"Test message"}' \
  https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN
```

### Rate Limiting

Discord has rate limits for webhooks:
- **5 requests per 2 seconds** for most webhooks
- The application includes built-in retry logic with exponential backoff
- If you're processing many tasks quickly, consider batching notifications

## Integration Examples

### Docker Compose

```yaml
version: '3.8'
services:
  allsafe-asm:
    build: .
    environment:
      - ENABLE_DISCORD_NOTIFICATIONS=true
      - DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK_URL}
      - DISCORD_WEBHOOK_TIMEOUT=30
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: allsafe-asm
spec:
  template:
    spec:
      containers:
      - name: allsafe-asm
        env:
        - name: ENABLE_DISCORD_NOTIFICATIONS
          value: "true"
        - name: DISCORD_WEBHOOK_URL
          valueFrom:
            secretKeyRef:
              name: discord-webhook-secret
              key: webhook-url
```

### Azure Container Instances

```bash
az container create \
  --resource-group myResourceGroup \
  --name allsafe-asm \
  --image allsafe-asm:latest \
  --environment-variables \
    ENABLE_DISCORD_NOTIFICATIONS=true \
    DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your-webhook-url
``` 
package azure

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/allsafeASM/api/internal/models"
	"github.com/google/uuid"
	"github.com/projectdiscovery/gologger"
)

// BlobStorageClient wraps Azure Blob Storage operations
type BlobStorageClient struct {
	client        *azblob.Client
	containerName string
}

// NewBlobStorageClient creates a new Blob Storage client
func NewBlobStorageClient(connectionString, containerName string) (*BlobStorageClient, error) {
	client, err := azblob.NewClientFromConnectionString(connectionString, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob storage client: %w", err)
	}

	return &BlobStorageClient{
		client:        client,
		containerName: containerName,
	}, nil
}

// StoreTaskResult stores a task result in blob storage
func (b *BlobStorageClient) StoreTaskResult(ctx context.Context, result *models.TaskResult) error {
	// Create a unique blob name using timestamp and task ID
	randomID := uuid.New().String()
	blobName := fmt.Sprintf("%s-%s/%s/out/%s.json", result.Domain, result.ScanID, result.Task, randomID)

	// Marshal the result to JSON
	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal task result: %w", err)
	}

	// Upload to blob storage
	_, err = b.client.UploadBuffer(ctx, b.containerName, blobName, resultJSON, &azblob.UploadBufferOptions{})
	if err != nil {
		return fmt.Errorf("failed to upload task result to blob storage: %w", err)
	}

	gologger.Info().Msgf("Stored task result in blob: %s/%s", b.containerName, blobName)
	return nil
}

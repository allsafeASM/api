package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/allsafeASM/api/internal/models"
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
	timestamp := time.Now().Format("2006-01-02-15-04-05")
	blobName := fmt.Sprintf("results/%s/%s-%s.json", result.TaskType, result.TaskID, timestamp)

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

// GetTaskResult retrieves a task result from blob storage
func (b *BlobStorageClient) GetTaskResult(ctx context.Context, blobName string) (*models.TaskResult, error) {
	// Download from blob storage
	response, err := b.client.DownloadStream(ctx, b.containerName, blobName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to download task result from blob storage: %w", err)
	}
	defer response.Body.Close()

	// Parse the JSON
	var result models.TaskResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode task result JSON: %w", err)
	}

	return &result, nil
}

// ListTaskResults lists all task results for a given task type
func (b *BlobStorageClient) ListTaskResults(ctx context.Context, taskType string) ([]string, error) {
	var blobNames []string

	pager := b.client.NewListBlobsFlatPager(b.containerName, &azblob.ListBlobsFlatOptions{
		Prefix: &[]string{fmt.Sprintf("results/%s/", taskType)}[0],
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list blobs: %w", err)
		}

		for _, blob := range page.Segment.BlobItems {
			blobNames = append(blobNames, *blob.Name)
		}
	}

	return blobNames, nil
}

// DeleteTaskResult deletes a task result from blob storage
func (b *BlobStorageClient) DeleteTaskResult(ctx context.Context, blobName string) error {
	_, err := b.client.DeleteBlob(ctx, b.containerName, blobName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete task result from blob storage: %w", err)
	}

	gologger.Info().Msgf("Deleted task result from blob: %s/%s", b.containerName, blobName)
	return nil
}
